"""
Sorel-20M Dataset Loader
Handles loading and preprocessing of the Sorel-20M malware dataset
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Iterator, Tuple, Optional, Dict
import json
import logging
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SorelDataLoader:
    """
    Loads Sorel-20M dataset with streaming support for large-scale training

    Dataset structure:
    - 10M samples (5M malware + 5M benign)
    - 2,381 features per sample
    - Labels: 0 (benign), 1 (malware)
    - Metadata: hashes, file types, timestamps
    """

    def __init__(
        self,
        data_dir: str = "./data/raw/sorel",
        cache_dir: str = "./data/processed/sorel"
    ):
        self.data_dir = Path(data_dir)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Dataset files
        self.metadata_path = self.data_dir / "sorel-20m-metadata.parquet"
        self.features_path = self.data_dir / "sorel-20m-features.npy"

        logger.info(f"Initialized SorelDataLoader with data_dir: {self.data_dir}")

    def load_metadata(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Load sample metadata

        Returns DataFrame with columns:
        - sha256: File hash
        - label: 0 (benign) or 1 (malware)
        - avclass: Antivirus classification
        - scan_date: When file was scanned
        - file_type: PE, ELF, Mach-O, etc.
        """
        logger.info("Loading metadata...")

        if not self.metadata_path.exists():
            raise FileNotFoundError(
                f"Metadata not found at {self.metadata_path}\n"
                f"Download from: https://sorel-20m.s3.amazonaws.com/sorel-20m-metadata.tar.gz"
            )

        df = pd.read_parquet(self.metadata_path)

        if limit:
            df = df.head(limit)

        logger.info(f"Loaded {len(df):,} samples")
        logger.info(f"Malware samples: {(df['label'] == 1).sum():,}")
        logger.info(f"Benign samples: {(df['label'] == 0).sum():,}")

        return df

    def load_features(
        self,
        batch_size: int = 10000,
        shuffle: bool = True,
        seed: int = 42
    ) -> Iterator[Tuple[np.ndarray, np.ndarray]]:
        """
        Load features in batches (memory-efficient streaming)

        Args:
            batch_size: Number of samples per batch
            shuffle: Whether to shuffle samples
            seed: Random seed for shuffling

        Yields:
            (features, labels) tuples of shape (batch_size, 2381) and (batch_size,)
        """
        logger.info("Loading features...")

        if not self.features_path.exists():
            raise FileNotFoundError(
                f"Features not found at {self.features_path}\n"
                f"Download from: https://sorel-20m.s3.amazonaws.com/sorel-20m-features.tar.gz"
            )

        # Memory-map the features (don't load all into RAM)
        features = np.load(self.features_path, mmap_mode='r')

        # Load labels
        metadata = self.load_metadata()
        labels = metadata['label'].values

        num_samples = len(features)
        indices = np.arange(num_samples)

        if shuffle:
            rng = np.random.RandomState(seed)
            rng.shuffle(indices)

        # Yield batches
        num_batches = (num_samples + batch_size - 1) // batch_size

        for i in tqdm(range(num_batches), desc="Loading batches"):
            start_idx = i * batch_size
            end_idx = min((i + 1) * batch_size, num_samples)

            batch_indices = indices[start_idx:end_idx]

            # Load batch into memory
            X_batch = features[batch_indices]
            y_batch = labels[batch_indices]

            yield X_batch, y_batch

    def load_full_dataset(
        self,
        train_split: float = 0.8,
        val_split: float = 0.1,
        test_split: float = 0.1,
        seed: int = 42
    ) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
        """
        Load entire dataset split into train/val/test

        WARNING: Requires ~100GB RAM for full dataset
        Use load_features() for streaming instead
        """
        logger.info("Loading full dataset (this may take a while)...")

        assert abs(train_split + val_split + test_split - 1.0) < 1e-6

        features = np.load(self.features_path)
        metadata = self.load_metadata()
        labels = metadata['label'].values

        # Shuffle and split
        num_samples = len(features)
        indices = np.arange(num_samples)

        rng = np.random.RandomState(seed)
        rng.shuffle(indices)

        train_end = int(num_samples * train_split)
        val_end = int(num_samples * (train_split + val_split))

        train_idx = indices[:train_end]
        val_idx = indices[train_end:val_end]
        test_idx = indices[val_end:]

        logger.info(f"Train: {len(train_idx):,} samples")
        logger.info(f"Val: {len(val_idx):,} samples")
        logger.info(f"Test: {len(test_idx):,} samples")

        return {
            'train': (features[train_idx], labels[train_idx]),
            'val': (features[val_idx], labels[val_idx]),
            'test': (features[test_idx], labels[test_idx])
        }

    def get_sample_by_hash(self, sha256: str) -> Optional[Dict]:
        """Get a specific sample by its SHA256 hash"""
        metadata = self.load_metadata()
        sample = metadata[metadata['sha256'] == sha256]

        if len(sample) == 0:
            return None

        sample_idx = sample.index[0]
        features = np.load(self.features_path, mmap_mode='r')

        return {
            'sha256': sha256,
            'label': sample['label'].iloc[0],
            'features': features[sample_idx],
            'metadata': sample.to_dict('records')[0]
        }


class EmberDataLoader:
    """
    Ember Dataset Loader (1.1M samples, 2,381 features)
    Alternative/complement to Sorel-20M
    """

    def __init__(self, data_dir: str = "./data/raw/ember"):
        self.data_dir = Path(data_dir)
        logger.info(f"Initialized EmberDataLoader with data_dir: {self.data_dir}")

    def load_dataset(self, version: str = "2018") -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
        """
        Load Ember dataset (2017 or 2018 version)

        Returns:
            Dictionary with 'train' and 'test' splits
        """
        import ember  # pip install ember

        logger.info(f"Loading Ember {version} dataset...")

        if version == "2018":
            X_train, y_train, X_test, y_test = ember.read_vectorized_features(str(self.data_dir))
        else:
            raise ValueError(f"Unsupported Ember version: {version}")

        logger.info(f"Train: {len(X_train):,} samples")
        logger.info(f"Test: {len(X_test):,} samples")

        return {
            'train': (X_train, y_train),
            'test': (X_test, y_test)
        }


if __name__ == "__main__":
    # Test the loader
    loader = SorelDataLoader()

    # Load metadata
    metadata = loader.load_metadata(limit=100)
    print(metadata.head())

    # Stream features in batches
    for i, (X_batch, y_batch) in enumerate(loader.load_features(batch_size=1000)):
        print(f"Batch {i}: X shape {X_batch.shape}, y shape {y_batch.shape}")
        if i >= 2:  # Just test first 3 batches
            break
