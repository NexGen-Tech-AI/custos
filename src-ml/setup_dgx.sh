#!/bin/bash
# DGX Spark Environment Setup Script
# Run this on DGX Spark to set up the ML training environment

set -e

echo "🚀 Setting up Custos ML Training Environment on DGX Spark"

# Check if running on DGX
if ! nvidia-smi &> /dev/null; then
    echo "⚠️  WARNING: nvidia-smi not found. Are you on DGX Spark?"
fi

# Create conda environment
echo "📦 Creating conda environment: custos-ml"
conda create -n custos-ml python=3.10 -y
conda activate custos-ml

# Install PyTorch with CUDA support
echo "🔥 Installing PyTorch with CUDA 11.8"
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Install ML packages
echo "📊 Installing ML frameworks"
pip install -r requirements.txt

# Create data directories
echo "📁 Creating data directories"
mkdir -p data/{raw,processed,features,models}
mkdir -p data/raw/{sorel,ember,malwarebazaar}
mkdir -p logs/{training,evaluation}
mkdir -p outputs/{models,onnx,reports}

# Download datasets (optional - commented out due to size)
echo "📥 Dataset download instructions:"
echo ""
echo "1. Sorel-20M (10M samples, ~300GB):"
echo "   wget https://sorel-20m.s3.amazonaws.com/sorel-20m-metadata.tar.gz"
echo "   wget https://sorel-20m.s3.amazonaws.com/sorel-20m-features.tar.gz"
echo ""
echo "2. Ember Dataset (1.1M samples, ~16GB):"
echo "   wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
echo ""
echo "3. MalwareBazaar (API access):"
echo "   Set MALWAREBAZAAR_API_KEY in .env"
echo ""

# Create .env template
cat > .env << 'EOF'
# API Keys
MALWAREBAZAAR_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Paths
DATA_DIR=./data
MODEL_DIR=./outputs/models
ONNX_DIR=./outputs/onnx

# Training Config
BATCH_SIZE=256
LEARNING_RATE=0.001
NUM_EPOCHS=50
NUM_WORKERS=8

# Weights & Biases (optional)
WANDB_PROJECT=custos-ml
WANDB_API_KEY=your_key_here
EOF

echo ""
echo "✅ Environment setup complete!"
echo ""
echo "Next steps:"
echo "1. conda activate custos-ml"
echo "2. Download datasets to data/raw/"
echo "3. Configure .env file"
echo "4. Run: python scripts/train_xgboost.py"
