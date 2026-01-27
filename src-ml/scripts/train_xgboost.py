#!/usr/bin/env python3
"""
XGBoost Baseline Training Script for DGX Spark

Trains a high-performance malware detection model using XGBoost
Target: 98%+ detection rate, <0.01% false positive rate

Usage:
    python train_xgboost.py --data-dir ./data/raw/sorel --output-dir ./outputs/models
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, Tuple
import json
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split
import joblib

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from data.loaders.sorel_loader import SorelDataLoader

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class XGBoostTrainer:
    """XGBoost malware detection model trainer"""

    def __init__(
        self,
        data_dir: str = "./data/raw/sorel",
        output_dir: str = "./outputs/models",
        use_gpu: bool = True
    ):
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.use_gpu = use_gpu
        self.model = None

        logger.info(f"Initialized XGBoostTrainer")
        logger.info(f"Data directory: {self.data_dir}")
        logger.info(f"Output directory: {self.output_dir}")
        logger.info(f"GPU enabled: {self.use_gpu}")

    def train(
        self,
        max_samples: int = None,
        test_size: float = 0.2,
        val_size: float = 0.1
    ) -> Dict:
        """
        Train XGBoost model

        Args:
            max_samples: Limit training data (None = use all)
            test_size: Test set proportion
            val_size: Validation set proportion

        Returns:
            Training metrics dictionary
        """
        logger.info("=" * 80)
        logger.info("XGBOOST TRAINING STARTED")
        logger.info("=" * 80)

        start_time = time.time()

        # Load data
        logger.info("\n[1/5] Loading dataset...")
        X_train, X_val, X_test, y_train, y_val, y_test = self._load_data(
            max_samples, test_size, val_size
        )

        # Create DMatrix for XGBoost (optimized format)
        logger.info("\n[2/5] Creating DMatrix...")
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dval = xgb.DMatrix(X_val, label=y_val)
        dtest = xgb.DMatrix(X_test, label=y_test)

        # Configure model parameters
        logger.info("\n[3/5] Configuring model...")
        params = self._get_model_params()

        # Train model
        logger.info("\n[4/5] Training model...")
        logger.info(f"Training samples: {len(X_train):,}")
        logger.info(f"Validation samples: {len(X_val):,}")
        logger.info(f"Test samples: {len(X_test):,}")

        evals = [(dtrain, 'train'), (dval, 'val')]
        evals_result = {}

        self.model = xgb.train(
            params,
            dtrain,
            num_boost_round=1000,
            evals=evals,
            evals_result=evals_result,
            early_stopping_rounds=50,
            verbose_eval=10
        )

        # Evaluate model
        logger.info("\n[5/5] Evaluating model...")
        metrics = self._evaluate(dtest, y_test)

        # Save model
        self._save_model(metrics)

        # Log final results
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

    def _load_data(
        self,
        max_samples: int,
        test_size: float,
        val_size: float
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Load and split dataset"""
        loader = SorelDataLoader(str(self.data_dir))

        # Load features and labels
        logger.info("Loading features (this may take a while)...")

        # For large datasets, use streaming
        if max_samples and max_samples < 1000000:
            # Small enough to load into memory
            features = np.load(loader.features_path)
            metadata = loader.load_metadata()
            labels = metadata['label'].values

            if max_samples:
                features = features[:max_samples]
                labels = labels[:max_samples]
        else:
            # Use full dataset or streaming
            features = np.load(loader.features_path)
            metadata = loader.load_metadata()
            labels = metadata['label'].values

        logger.info(f"Loaded {len(features):,} samples with {features.shape[1]} features")
        logger.info(f"Malware samples: {(labels == 1).sum():,}")
        logger.info(f"Benign samples: {(labels == 0).sum():,}")

        # Split data: train / (val + test)
        X_train, X_temp, y_train, y_temp = train_test_split(
            features, labels,
            test_size=(test_size + val_size),
            stratify=labels,
            random_state=42
        )

        # Split temp into val / test
        val_ratio = val_size / (test_size + val_size)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp,
            test_size=(1 - val_ratio),
            stratify=y_temp,
            random_state=42
        )

        return X_train, X_val, X_test, y_train, y_val, y_test

    def _get_model_params(self) -> Dict:
        """Get XGBoost hyperparameters optimized for malware detection"""
        params = {
            # Task
            'objective': 'binary:logistic',
            'eval_metric': ['logloss', 'auc', 'error'],

            # Tree parameters
            'max_depth': 8,
            'min_child_weight': 5,
            'gamma': 0.1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,

            # Learning
            'learning_rate': 0.1,
            'alpha': 1.0,  # L1 regularization
            'lambda': 1.0,  # L2 regularization

            # Performance
            'n_jobs': -1,
            'random_state': 42,
        }

        # GPU acceleration
        if self.use_gpu:
            params['tree_method'] = 'gpu_hist'
            params['predictor'] = 'gpu_predictor'
            logger.info("GPU acceleration enabled")
        else:
            params['tree_method'] = 'hist'

        return params

    def _evaluate(self, dtest: xgb.DMatrix, y_test: np.ndarray) -> Dict:
        """Evaluate model on test set"""
        # Predict probabilities
        y_pred_proba = self.model.predict(dtest)

        # Predict classes (threshold = 0.5)
        y_pred = (y_pred_proba >= 0.5).astype(int)

        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_proba)

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        # False positive rate (critical for malware detection)
        fpr = fp / (fp + tn)

        metrics = {
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

        # Print classification report
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))

        logger.info("\nConfusion Matrix:")
        logger.info(f"  True Negatives:  {tn:,}")
        logger.info(f"  False Positives: {fp:,}")
        logger.info(f"  False Negatives: {fn:,}")
        logger.info(f"  True Positives:  {tp:,}")

        # Feature importance
        importance = self.model.get_score(importance_type='gain')
        top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:20]

        logger.info("\nTop 20 Features by Gain:")
        for i, (feat, gain) in enumerate(top_features, 1):
            logger.info(f"  {i:2d}. {feat}: {gain:.2f}")

        metrics['feature_importance'] = importance

        return metrics

    def _save_model(self, metrics: Dict):
        """Save model and metadata"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Save XGBoost model
        model_path = self.output_dir / f"xgboost_malware_{timestamp}.json"
        self.model.save_model(str(model_path))
        logger.info(f"\nSaved XGBoost model: {model_path}")

        # Save as pickle (for sklearn compatibility)
        pickle_path = self.output_dir / f"xgboost_malware_{timestamp}.pkl"
        joblib.dump(self.model, str(pickle_path))
        logger.info(f"Saved pickle model: {pickle_path}")

        # Save metadata
        metadata = {
            'timestamp': timestamp,
            'model_type': 'XGBoost',
            'metrics': metrics,
            'num_features': 2381,
            'training_data': 'Sorel-20M',
        }

        metadata_path = self.output_dir / f"xgboost_malware_{timestamp}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Saved metadata: {metadata_path}")

        # Export to ONNX (for production inference)
        try:
            self._export_onnx(timestamp)
        except Exception as e:
            logger.warning(f"Failed to export ONNX: {e}")

    def _export_onnx(self, timestamp: str):
        """Export model to ONNX format"""
        from onnxmltools.convert import convert_xgboost
        from onnxmltools.convert.common.data_types import FloatTensorType

        # Define input shape
        initial_type = [('float_input', FloatTensorType([None, 2381]))]

        # Convert to ONNX
        onnx_model = convert_xgboost(self.model, initial_types=initial_type)

        # Save
        onnx_path = self.output_dir.parent / "onnx" / f"xgboost_malware_{timestamp}.onnx"
        onnx_path.parent.mkdir(parents=True, exist_ok=True)

        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        logger.info(f"Exported ONNX model: {onnx_path}")


def main():
    parser = argparse.ArgumentParser(description="Train XGBoost malware detection model")
    parser.add_argument(
        '--data-dir',
        type=str,
        default='./data/raw/sorel',
        help='Path to Sorel-20M dataset'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='./outputs/models',
        help='Output directory for models'
    )
    parser.add_argument(
        '--max-samples',
        type=int,
        default=None,
        help='Maximum number of samples to use (for testing)'
    )
    parser.add_argument(
        '--no-gpu',
        action='store_true',
        help='Disable GPU acceleration'
    )
    parser.add_argument(
        '--test-size',
        type=float,
        default=0.2,
        help='Test set proportion (default: 0.2)'
    )
    parser.add_argument(
        '--val-size',
        type=float,
        default=0.1,
        help='Validation set proportion (default: 0.1)'
    )

    args = parser.parse_args()

    # Train model
    trainer = XGBoostTrainer(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        use_gpu=not args.no_gpu
    )

    metrics = trainer.train(
        max_samples=args.max_samples,
        test_size=args.test_size,
        val_size=args.val_size
    )

    logger.info("\n✅ Training complete!")
    logger.info(f"Detection rate: {metrics['recall']:.2%}")
    logger.info(f"False positive rate: {metrics['fpr']:.4%}")


if __name__ == "__main__":
    main()
