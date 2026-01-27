# Custos ML Training Pipeline

Machine learning training pipeline for elite malware detection on DGX Spark.

## Overview

This ML pipeline trains high-performance malware detection models:
- **XGBoost**: 98%+ detection rate baseline
- **Neural Networks**: 99.5%+ detection rate with ensemble
- **Target**: <0.01% false positive rate
- **Deployment**: ONNX models for real-time inference

## Project Structure

```
src-ml/
├── data/
│   ├── loaders/              # Dataset loaders (Sorel-20M, Ember)
│   ├── preprocessors/        # Data preprocessing utilities
│   └── validators/           # Data validation
│
├── features/
│   ├── extractors/           # Feature extraction (PE, ELF, etc.)
│   ├── builders/             # Feature engineering
│   └── selectors/            # Feature selection
│
├── models/
│   ├── xgboost/              # XGBoost models
│   ├── neural/               # PyTorch models
│   └── ensemble/             # Ensemble methods
│
├── training/
│   ├── trainers/             # Training orchestration
│   └── callbacks/            # Training callbacks
│
├── evaluation/
│   ├── metrics/              # Custom metrics
│   └── validators/           # Model validation
│
├── serving/
│   ├── exporters/            # ONNX export
│   └── deployers/            # Model deployment
│
├── optimization/
│   └── hyperparameter/       # Hyperparameter tuning
│
├── scripts/
│   ├── train_xgboost.py      # XGBoost training script
│   ├── train_neural_net.py   # Neural network training
│   ├── export_onnx.py        # Export to ONNX
│   └── benchmark.py          # Performance benchmarking
│
└── configs/                  # Configuration files
```

## Quick Start

### 1. Setup Environment (DGX Spark)

```bash
# Clone repo and navigate to ML directory
cd src-ml

# Run setup script
./setup_dgx.sh

# Activate environment
conda activate custos-ml
```

### 2. Download Datasets

**Sorel-20M** (10M samples, ~300GB):
```bash
cd data/raw/sorel
wget https://sorel-20m.s3.amazonaws.com/sorel-20m-metadata.tar.gz
wget https://sorel-20m.s3.amazonaws.com/sorel-20m-features.tar.gz
tar -xzf sorel-20m-metadata.tar.gz
tar -xzf sorel-20m-features.tar.gz
```

**Ember Dataset** (1.1M samples, ~16GB):
```bash
cd data/raw/ember
wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xjf ember_dataset_2018_2.tar.bz2
```

### 3. Train Models

**XGBoost Baseline** (fastest, 98%+ accuracy):
```bash
python scripts/train_xgboost.py \
    --data-dir ./data/raw/sorel \
    --output-dir ./outputs/models
```

**Neural Network** (best accuracy, 99.5%+):
```bash
# MLP (fastest neural network)
python scripts/train_neural_net.py --model mlp --epochs 50

# CNN (pattern detection)
python scripts/train_neural_net.py --model cnn --epochs 50

# Transformer (contextual analysis)
python scripts/train_neural_net.py --model transformer --epochs 50

# Ensemble (best performance)
python scripts/train_neural_net.py --model ensemble --epochs 100
```

### 4. Export to ONNX

```bash
python scripts/export_onnx.py \
    --model-path ./outputs/models/ensemble_malware_latest.pth \
    --output-path ./outputs/onnx/malware_detector.onnx
```

## Training Details

### XGBoost

**Hyperparameters**:
```python
{
    'objective': 'binary:logistic',
    'max_depth': 8,
    'learning_rate': 0.1,
    'tree_method': 'gpu_hist',  # GPU acceleration
    'n_estimators': 1000,
}
```

**Training Time**: ~2-4 hours on DGX Spark (A100)
**Expected Performance**:
- Accuracy: 98.5%+
- Precision: 98.0%+
- Recall: 99.0%+
- FPR: <0.02%

### Neural Network Ensemble

**Architecture**:
- **MLP**: 3-layer feedforward (1024 → 512 → 256)
- **CNN**: 1D convolution for pattern detection
- **Transformer**: Self-attention for contextual features
- **Meta-Learner**: Combines predictions with learned weights

**Training Time**: ~8-12 hours on DGX Spark (8× A100)
**Expected Performance**:
- Accuracy: 99.5%+
- Precision: 99.3%+
- Recall: 99.7%+
- FPR: <0.01%

## Feature Engineering

### Static Features (2,381 features)

Extracted from PE/ELF/Mach-O binaries:

1. **File Metadata** (50 features)
   - File size, entropy, hashes (MD5, SHA1, SHA256)
   - Magic bytes, file type
   - Timestamps

2. **PE Headers** (200 features)
   - DOS header, NT header, Optional header
   - Section characteristics
   - Security features (ASLR, DEP, SEH)

3. **Imports/Exports** (500 features)
   - DLL imports (top 500 most common)
   - API call frequency
   - Suspicious API detection

4. **Sections** (300 features)
   - Section names, sizes, entropy
   - Code/data ratio
   - Executable characteristics

5. **Strings** (200 features)
   - String count, length statistics
   - URL/IP/email detection
   - Suspicious keywords

6. **Resources** (100 features)
   - Resource types, sizes
   - Icon/manifest/version info

7. **Code Characteristics** (500 features)
   - Opcode n-grams
   - Control flow features
   - API call sequences

8. **Behavioral Indicators** (500 features)
   - Packing detection
   - Anti-analysis techniques
   - Persistence mechanisms

## Datasets

### Sorel-20M

- **Size**: 10 million samples (5M malware + 5M benign)
- **Features**: 2,381 static features
- **Format**: NumPy arrays + Parquet metadata
- **Source**: https://github.com/sophos/SOREL-20M

### Ember

- **Size**: 1.1 million samples
- **Features**: 2,381 static features
- **Format**: Vectorized features
- **Source**: https://github.com/elastic/ember

### MalwareBazaar

- **Live feed**: Daily malware samples
- **API**: Real-time threat intelligence
- **Source**: https://bazaar.abuse.ch/

## Model Evaluation

### Metrics

We track the following metrics:
- **Accuracy**: Overall correctness
- **Precision**: False positive rate (most critical for us)
- **Recall**: Detection rate (true positive rate)
- **F1 Score**: Harmonic mean of precision/recall
- **ROC-AUC**: Area under ROC curve
- **FPR**: False positive rate (<0.01% target)

### Confusion Matrix

```
                 Predicted
                Benign  Malware
Actual Benign    TN      FP      ← Minimize FP!
       Malware   FN      TP      ← Maximize TP!
```

**Target**:
- True Positives (TP): 99.5%+ of malware detected
- False Positives (FP): <0.01% of benign flagged
- False Negatives (FN): <0.5% of malware missed
- True Negatives (TN): 99.99%+ of benign correctly identified

## Production Deployment

### ONNX Export

Models are exported to ONNX format for:
- **Cross-platform**: Run on Linux/Windows/macOS
- **Language agnostic**: Use from Rust/C++/Python/JavaScript
- **Optimized**: Hardware-accelerated inference
- **Small size**: <100MB models

### Inference Performance

**Target Latency** (on consumer hardware):
- XGBoost: <5ms per file
- Neural Network: <10ms per file
- Ensemble: <15ms per file

**Throughput**:
- >1000 files/second (on-access scanning)
- >10,000 files/second (full system scan)

## Monitoring & Logging

### Weights & Biases Integration

Track training metrics in real-time:
```bash
export WANDB_API_KEY=your_key_here
export WANDB_PROJECT=custos-ml

python scripts/train_neural_net.py --model ensemble --epochs 50
```

View metrics at: https://wandb.ai/your-username/custos-ml

### TensorBoard

Local training visualization:
```bash
tensorboard --logdir ./logs
```

## Advanced Topics

### Hyperparameter Tuning

Use Optuna for automated hyperparameter search:
```bash
python scripts/optimize_hyperparameters.py \
    --model xgboost \
    --trials 100 \
    --timeout 3600
```

### Transfer Learning

Fine-tune pre-trained models on custom datasets:
```bash
python scripts/finetune.py \
    --pretrained ./outputs/models/ensemble_base.pth \
    --data-dir ./data/custom \
    --epochs 10
```

### Model Compression

Reduce model size for edge deployment:
```bash
# Quantization (INT8)
python scripts/quantize.py \
    --model ./outputs/onnx/malware_detector.onnx \
    --output ./outputs/onnx/malware_detector_int8.onnx

# Pruning (remove weights)
python scripts/prune.py \
    --model ./outputs/models/ensemble.pth \
    --sparsity 0.5 \
    --output ./outputs/models/ensemble_pruned.pth
```

## Troubleshooting

### Out of Memory

If you run out of GPU memory:
```bash
# Reduce batch size
python scripts/train_neural_net.py --batch-size 128

# Use gradient checkpointing
python scripts/train_neural_net.py --gradient-checkpointing

# Use mixed precision training
python scripts/train_neural_net.py --fp16
```

### Slow Training

If training is slow:
```bash
# Use more workers
python scripts/train_neural_net.py --num-workers 16

# Enable pin memory
python scripts/train_neural_net.py --pin-memory

# Use smaller model
python scripts/train_neural_net.py --model mlp  # Instead of ensemble
```

## Contributing

When adding new models:
1. Create model class in `models/`
2. Add training script in `scripts/`
3. Export to ONNX in `serving/exporters/`
4. Add tests in `tests/`
5. Update this README

## Support

For issues or questions:
- Internal: See IMPLEMENTATION_PLAN.md
- External: Contact security@custos.ai

## License

Proprietary - Custos Security Platform
All rights reserved.

---

**Last Updated**: January 26, 2026
**Version**: 0.1.0
**Status**: Development
