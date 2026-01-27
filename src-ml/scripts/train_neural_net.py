#!/usr/bin/env python3
"""
Neural Network Ensemble Training for DGX Spark

Trains deep learning models for malware detection
Target: 99.5%+ detection rate, <0.01% false positive rate

Models:
- MLP: Multi-layer perceptron (baseline)
- CNN: Convolutional neural network (pattern detection)
- Transformer: Self-attention mechanism (contextual analysis)
- Ensemble: Combines all models

Usage:
    python train_neural_net.py --model ensemble --epochs 50
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, Tuple
import json
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
from tqdm import tqdm

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from data.loaders.sorel_loader import SorelDataLoader

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MalwareDataset(Dataset):
    """PyTorch dataset for malware detection"""

    def __init__(self, features: np.ndarray, labels: np.ndarray):
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]


class MLP(nn.Module):
    """Multi-Layer Perceptron for malware detection"""

    def __init__(self, input_dim: int = 2381, hidden_dims: list = [1024, 512, 256]):
        super().__init__()

        layers = []
        prev_dim = input_dim

        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.3)
            ])
            prev_dim = hidden_dim

        layers.append(nn.Linear(prev_dim, 2))  # Binary classification

        self.model = nn.Sequential(*layers)

    def forward(self, x):
        return self.model(x)


class CNN1D(nn.Module):
    """1D CNN for pattern detection in feature vectors"""

    def __init__(self, input_dim: int = 2381):
        super().__init__()

        # Reshape features into channels for CNN
        self.conv1 = nn.Conv1d(1, 64, kernel_size=5, padding=2)
        self.bn1 = nn.BatchNorm1d(64)

        self.conv2 = nn.Conv1d(64, 128, kernel_size=5, padding=2)
        self.bn2 = nn.BatchNorm1d(128)

        self.conv3 = nn.Conv1d(128, 256, kernel_size=5, padding=2)
        self.bn3 = nn.BatchNorm1d(256)

        self.pool = nn.AdaptiveMaxPool1d(1)

        self.fc = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 2)
        )

    def forward(self, x):
        # Reshape: (batch, features) -> (batch, 1, features)
        x = x.unsqueeze(1)

        # Conv layers
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.max_pool1d(x, 2)

        x = F.relu(self.bn2(self.conv2(x)))
        x = F.max_pool1d(x, 2)

        x = F.relu(self.bn3(self.conv3(x)))

        # Global pooling
        x = self.pool(x)
        x = x.squeeze(-1)

        # Fully connected
        x = self.fc(x)

        return x


class TransformerEncoder(nn.Module):
    """Transformer for contextual feature analysis"""

    def __init__(self, input_dim: int = 2381, num_heads: int = 8):
        super().__init__()

        self.embedding_dim = 256
        self.num_heads = num_heads

        # Project features to embedding space
        self.input_proj = nn.Linear(input_dim, self.embedding_dim)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=self.embedding_dim,
            nhead=num_heads,
            dim_feedforward=1024,
            dropout=0.1,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=4)

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(self.embedding_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 2)
        )

    def forward(self, x):
        # Project to embedding space
        x = self.input_proj(x)

        # Add batch dimension for transformer (seq_len = 1)
        x = x.unsqueeze(1)

        # Transformer encoding
        x = self.transformer(x)

        # Take first token (since seq_len = 1)
        x = x.squeeze(1)

        # Classify
        x = self.classifier(x)

        return x


class EnsembleModel(nn.Module):
    """Ensemble of MLP + CNN + Transformer"""

    def __init__(self, input_dim: int = 2381):
        super().__init__()

        self.mlp = MLP(input_dim)
        self.cnn = CNN1D(input_dim)
        self.transformer = TransformerEncoder(input_dim)

        # Meta-learner (weighted voting)
        self.meta = nn.Linear(6, 2)  # 3 models × 2 classes

    def forward(self, x):
        mlp_out = self.mlp(x)
        cnn_out = self.cnn(x)
        transformer_out = self.transformer(x)

        # Concatenate predictions
        combined = torch.cat([mlp_out, cnn_out, transformer_out], dim=1)

        # Meta-learner combines predictions
        out = self.meta(combined)

        return out


class NeuralNetTrainer:
    """Neural network training orchestrator"""

    def __init__(
        self,
        model_type: str = 'mlp',
        data_dir: str = './data/raw/sorel',
        output_dir: str = './outputs/models',
        device: str = 'cuda'
    ):
        self.model_type = model_type
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.device = torch.device(device if torch.cuda.is_available() else 'cpu')

        logger.info(f"Initialized NeuralNetTrainer")
        logger.info(f"Model type: {model_type}")
        logger.info(f"Device: {self.device}")

    def train(
        self,
        epochs: int = 50,
        batch_size: int = 256,
        learning_rate: float = 0.001,
        max_samples: int = None
    ) -> Dict:
        """Train neural network"""
        logger.info("=" * 80)
        logger.info(f"NEURAL NETWORK TRAINING STARTED ({self.model_type.upper()})")
        logger.info("=" * 80)

        start_time = time.time()

        # Load data
        logger.info("\n[1/5] Loading dataset...")
        train_loader, val_loader, test_loader = self._prepare_data(batch_size, max_samples)

        # Create model
        logger.info(f"\n[2/5] Creating {self.model_type} model...")
        model = self._create_model()
        model = model.to(self.device)

        num_params = sum(p.numel() for p in model.parameters())
        logger.info(f"Model parameters: {num_params:,}")

        # Optimizer and scheduler
        optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
        scheduler = CosineAnnealingLR(optimizer, T_max=epochs)

        # Loss function (weighted for imbalanced classes)
        criterion = nn.CrossEntropyLoss()

        # Training loop
        logger.info("\n[3/5] Training...")
        best_val_loss = float('inf')
        best_model_state = None

        for epoch in range(epochs):
            # Train
            train_loss, train_acc = self._train_epoch(
                model, train_loader, criterion, optimizer
            )

            # Validate
            val_loss, val_acc = self._validate(model, val_loader, criterion)

            scheduler.step()

            # Log
            logger.info(
                f"Epoch {epoch+1}/{epochs} | "
                f"Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} | "
                f"Val Loss: {val_loss:.4f} Acc: {val_acc:.4f}"
            )

            # Save best model
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_model_state = model.state_dict().copy()
                logger.info(f"  → New best model (val_loss: {val_loss:.4f})")

        # Load best model
        model.load_state_dict(best_model_state)

        # Evaluate on test set
        logger.info("\n[4/5] Evaluating on test set...")
        metrics = self._evaluate(model, test_loader)

        # Save model
        logger.info("\n[5/5] Saving model...")
        self._save_model(model, metrics)

        # Final results
        elapsed = time.time() - start_time
        logger.info("\n" + "=" * 80)
        logger.info("TRAINING COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Time elapsed: {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
        logger.info(f"\nFinal Metrics:")
        logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall:    {metrics['recall']:.4f}")
        logger.info(f"  F1 Score:  {metrics['f1']:.4f}")
        logger.info(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        logger.info(f"  FPR:       {metrics['fpr']:.6f}")
        logger.info("=" * 80)

        return metrics

    def _prepare_data(self, batch_size: int, max_samples: int):
        """Prepare data loaders"""
        loader = SorelDataLoader(str(self.data_dir))

        # Load data
        features = np.load(loader.features_path)
        metadata = loader.load_metadata()
        labels = metadata['label'].values

        if max_samples:
            features = features[:max_samples]
            labels = labels[:max_samples]

        # Split data
        from sklearn.model_selection import train_test_split

        X_train, X_temp, y_train, y_temp = train_test_split(
            features, labels, test_size=0.3, stratify=labels, random_state=42
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
        )

        logger.info(f"Train: {len(X_train):,} samples")
        logger.info(f"Val:   {len(X_val):,} samples")
        logger.info(f"Test:  {len(X_test):,} samples")

        # Create datasets
        train_dataset = MalwareDataset(X_train, y_train)
        val_dataset = MalwareDataset(X_val, y_val)
        test_dataset = MalwareDataset(X_test, y_test)

        # Create data loaders
        train_loader = DataLoader(
            train_dataset, batch_size=batch_size, shuffle=True, num_workers=4
        )
        val_loader = DataLoader(
            val_dataset, batch_size=batch_size, shuffle=False, num_workers=4
        )
        test_loader = DataLoader(
            test_dataset, batch_size=batch_size, shuffle=False, num_workers=4
        )

        return train_loader, val_loader, test_loader

    def _create_model(self):
        """Create model based on type"""
        if self.model_type == 'mlp':
            return MLP()
        elif self.model_type == 'cnn':
            return CNN1D()
        elif self.model_type == 'transformer':
            return TransformerEncoder()
        elif self.model_type == 'ensemble':
            return EnsembleModel()
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")

    def _train_epoch(self, model, loader, criterion, optimizer):
        """Train for one epoch"""
        model.train()
        total_loss = 0
        correct = 0
        total = 0

        pbar = tqdm(loader, desc="Training")
        for features, labels in pbar:
            features = features.to(self.device)
            labels = labels.to(self.device)

            # Forward
            optimizer.zero_grad()
            outputs = model(features)
            loss = criterion(outputs, labels)

            # Backward
            loss.backward()
            optimizer.step()

            # Metrics
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += labels.size(0)
            correct += predicted.eq(labels).sum().item()

            pbar.set_postfix({'loss': loss.item(), 'acc': correct / total})

        return total_loss / len(loader), correct / total

    def _validate(self, model, loader, criterion):
        """Validate model"""
        model.eval()
        total_loss = 0
        correct = 0
        total = 0

        with torch.no_grad():
            for features, labels in loader:
                features = features.to(self.device)
                labels = labels.to(self.device)

                outputs = model(features)
                loss = criterion(outputs, labels)

                total_loss += loss.item()
                _, predicted = outputs.max(1)
                total += labels.size(0)
                correct += predicted.eq(labels).sum().item()

        return total_loss / len(loader), correct / total

    def _evaluate(self, model, loader):
        """Evaluate model on test set"""
        model.eval()

        all_preds = []
        all_probs = []
        all_labels = []

        with torch.no_grad():
            for features, labels in tqdm(loader, desc="Evaluating"):
                features = features.to(self.device)

                outputs = model(features)
                probs = F.softmax(outputs, dim=1)[:, 1]  # Probability of malware

                _, predicted = outputs.max(1)

                all_preds.extend(predicted.cpu().numpy())
                all_probs.extend(probs.cpu().numpy())
                all_labels.extend(labels.numpy())

        all_preds = np.array(all_preds)
        all_probs = np.array(all_probs)
        all_labels = np.array(all_labels)

        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_preds)
        precision = precision_score(all_labels, all_preds)
        recall = recall_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds)
        roc_auc = roc_auc_score(all_labels, all_probs)

        # Confusion matrix
        cm = confusion_matrix(all_labels, all_preds)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn)

        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'roc_auc': float(roc_auc),
            'fpr': float(fpr),
            'confusion_matrix': {
                'tn': int(tn),
                'fp': int(fp),
                'fn': int(fn),
                'tp': int(tp)
            }
        }

    def _save_model(self, model, metrics):
        """Save model and metadata"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Save PyTorch model
        model_path = self.output_dir / f"{self.model_type}_malware_{timestamp}.pth"
        torch.save(model.state_dict(), model_path)
        logger.info(f"Saved PyTorch model: {model_path}")

        # Save metadata
        metadata = {
            'timestamp': timestamp,
            'model_type': self.model_type,
            'metrics': metrics,
            'num_features': 2381,
            'training_data': 'Sorel-20M',
        }

        metadata_path = self.output_dir / f"{self.model_type}_malware_{timestamp}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Saved metadata: {metadata_path}")

        # Export to ONNX
        try:
            self._export_onnx(model, timestamp)
        except Exception as e:
            logger.warning(f"Failed to export ONNX: {e}")

    def _export_onnx(self, model, timestamp):
        """Export model to ONNX format"""
        model.eval()

        # Dummy input
        dummy_input = torch.randn(1, 2381).to(self.device)

        # Export
        onnx_path = self.output_dir.parent / "onnx" / f"{self.model_type}_malware_{timestamp}.onnx"
        onnx_path.parent.mkdir(parents=True, exist_ok=True)

        torch.onnx.export(
            model,
            dummy_input,
            str(onnx_path),
            input_names=['features'],
            output_names=['predictions'],
            dynamic_axes={'features': {0: 'batch_size'}}
        )

        logger.info(f"Exported ONNX model: {onnx_path}")


def main():
    parser = argparse.ArgumentParser(description="Train neural network malware detector")
    parser.add_argument(
        '--model',
        type=str,
        choices=['mlp', 'cnn', 'transformer', 'ensemble'],
        default='mlp',
        help='Model architecture'
    )
    parser.add_argument('--epochs', type=int, default=50, help='Number of epochs')
    parser.add_argument('--batch-size', type=int, default=256, help='Batch size')
    parser.add_argument('--lr', type=float, default=0.001, help='Learning rate')
    parser.add_argument('--max-samples', type=int, default=None, help='Max samples')
    parser.add_argument('--device', type=str, default='cuda', help='Device (cuda/cpu)')

    args = parser.parse_args()

    trainer = NeuralNetTrainer(
        model_type=args.model,
        device=args.device
    )

    metrics = trainer.train(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        max_samples=args.max_samples
    )

    logger.info("\n✅ Training complete!")


if __name__ == "__main__":
    main()
