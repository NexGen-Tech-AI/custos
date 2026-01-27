#!/usr/bin/env python3
"""
YARA Rule Downloader

Downloads community YARA rules from multiple sources:
- YaraRules Project (5000+ rules)
- Awesome YARA (curated collection)
- Signature-Base (Florian Roth)
- Custom rules

Usage:
    python download_yara_rules.py --output-dir ../data/yara_rules
"""

import argparse
import os
import subprocess
import logging
from pathlib import Path
import requests
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# YARA rule repositories
YARA_REPOS = [
    {
        'name': 'YaraRules',
        'url': 'https://github.com/Yara-Rules/rules.git',
        'description': '5000+ community YARA rules',
    },
    {
        'name': 'Signature-Base',
        'url': 'https://github.com/Neo23x0/signature-base.git',
        'description': 'Florian Roth signature database',
    },
    {
        'name': 'Awesome-YARA',
        'url': 'https://github.com/InQuest/awesome-yara.git',
        'description': 'Curated YARA rule collection',
    },
    {
        'name': 'Malware-YARA-Rules',
        'url': 'https://github.com/Yara-Rules/rules.git',
        'description': 'Malware-specific rules',
    },
]

class YaraRuleDownloader:
    """Downloads and organizes YARA rules"""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.raw_dir = self.output_dir / 'raw'
        self.compiled_dir = self.output_dir / 'compiled'
        self.curated_dir = self.output_dir / 'curated'

        self.raw_dir.mkdir(exist_ok=True)
        self.compiled_dir.mkdir(exist_ok=True)
        self.curated_dir.mkdir(exist_ok=True)

    def download_all(self):
        """Download all YARA rule repositories"""
        logger.info("Starting YARA rule download...")

        total_rules = 0

        for repo in YARA_REPOS:
            try:
                count = self.download_repo(repo)
                total_rules += count
            except Exception as e:
                logger.error(f"Failed to download {repo['name']}: {e}")

        logger.info(f"\n✅ Total rules downloaded: {total_rules:,}")

        # Curate and organize rules
        self.curate_rules()

        # Generate index
        self.generate_index()

    def download_repo(self, repo: dict) -> int:
        """Download a single repository"""
        logger.info(f"\n📥 Downloading {repo['name']}...")
        logger.info(f"   {repo['description']}")

        repo_dir = self.raw_dir / repo['name']

        # Clone or update repository
        if repo_dir.exists():
            logger.info("   Repository exists, updating...")
            subprocess.run(
                ['git', 'pull'],
                cwd=repo_dir,
                capture_output=True,
                check=True
            )
        else:
            logger.info("   Cloning repository...")
            subprocess.run(
                ['git', 'clone', repo['url'], str(repo_dir)],
                capture_output=True,
                check=True
            )

        # Count YARA rules
        rule_count = sum(1 for _ in repo_dir.rglob('*.yar')) + \
                     sum(1 for _ in repo_dir.rglob('*.yara'))

        logger.info(f"   ✅ Found {rule_count:,} rules")

        return rule_count

    def curate_rules(self):
        """Organize rules by category"""
        logger.info("\n📂 Curating rules by category...")

        categories = {
            'ransomware': [],
            'trojan': [],
            'backdoor': [],
            'packer': [],
            'webshell': [],
            'cryptominer': [],
            'apt': [],
            'exploit': [],
            'malware': [],
        }

        # Scan all .yar and .yara files
        for rule_file in self.raw_dir.rglob('*.yar'):
            self._categorize_rule(rule_file, categories)

        for rule_file in self.raw_dir.rglob('*.yara'):
            self._categorize_rule(rule_file, categories)

        # Copy categorized rules
        for category, files in categories.items():
            if not files:
                continue

            category_dir = self.curated_dir / category
            category_dir.mkdir(exist_ok=True)

            logger.info(f"   {category}: {len(files)} rules")

            for src_file in files:
                dst_file = category_dir / src_file.name
                try:
                    import shutil
                    shutil.copy2(src_file, dst_file)
                except Exception as e:
                    logger.error(f"Failed to copy {src_file}: {e}")

    def _categorize_rule(self, rule_file: Path, categories: dict):
        """Categorize a rule file"""
        try:
            content = rule_file.read_text(errors='ignore').lower()

            # Simple keyword-based categorization
            if 'ransomware' in content or 'ransom' in content:
                categories['ransomware'].append(rule_file)
            elif 'trojan' in content:
                categories['trojan'].append(rule_file)
            elif 'backdoor' in content or 'rat' in content:
                categories['backdoor'].append(rule_file)
            elif 'packer' in content or 'upx' in content or 'packed' in content:
                categories['packer'].append(rule_file)
            elif 'webshell' in content or 'shell' in content:
                categories['webshell'].append(rule_file)
            elif 'miner' in content or 'crypto' in content:
                categories['cryptominer'].append(rule_file)
            elif 'apt' in content:
                categories['apt'].append(rule_file)
            elif 'exploit' in content or 'cve' in content:
                categories['exploit'].append(rule_file)
            else:
                categories['malware'].append(rule_file)

        except Exception as e:
            logger.error(f"Failed to categorize {rule_file}: {e}")

    def generate_index(self):
        """Generate index of all rules"""
        logger.info("\n📋 Generating index...")

        index = {
            'total_rules': 0,
            'categories': {},
            'sources': [repo['name'] for repo in YARA_REPOS],
        }

        for category_dir in self.curated_dir.iterdir():
            if not category_dir.is_dir():
                continue

            category = category_dir.name
            rules = list(category_dir.glob('*.yar')) + list(category_dir.glob('*.yara'))

            index['categories'][category] = {
                'count': len(rules),
                'files': [r.name for r in rules]
            }

            index['total_rules'] += len(rules)

        # Save index
        index_file = self.output_dir / 'index.json'
        with open(index_file, 'w') as f:
            json.dump(index, f, indent=2)

        logger.info(f"   ✅ Index saved: {index_file}")
        logger.info(f"   Total rules: {index['total_rules']:,}")

        # Print summary
        logger.info("\n📊 Category Summary:")
        for category, info in sorted(index['categories'].items()):
            logger.info(f"   {category:15s}: {info['count']:,} rules")

    def create_master_rule(self):
        """Create master YARA rule file (all rules combined)"""
        logger.info("\n🔨 Creating master rule file...")

        master_file = self.compiled_dir / 'master_rules.yar'

        with open(master_file, 'w') as master:
            master.write("// Custos Master YARA Rules\n")
            master.write("// Auto-generated - Do not edit manually\n\n")

            for yar_file in self.curated_dir.rglob('*.yar'):
                try:
                    master.write(f"// Source: {yar_file.relative_to(self.curated_dir)}\n")
                    master.write(yar_file.read_text())
                    master.write("\n\n")
                except Exception as e:
                    logger.error(f"Failed to include {yar_file}: {e}")

            for yara_file in self.curated_dir.rglob('*.yara'):
                try:
                    master.write(f"// Source: {yara_file.relative_to(self.curated_dir)}\n")
                    master.write(yara_file.read_text())
                    master.write("\n\n")
                except Exception as e:
                    logger.error(f"Failed to include {yara_file}: {e}")

        logger.info(f"   ✅ Master rule file: {master_file}")
        logger.info(f"   Size: {master_file.stat().st_size / 1024 / 1024:.1f} MB")


def main():
    parser = argparse.ArgumentParser(description="Download YARA rules")
    parser.add_argument(
        '--output-dir',
        type=str,
        default='../data/yara_rules',
        help='Output directory for YARA rules'
    )
    parser.add_argument(
        '--create-master',
        action='store_true',
        help='Create master rule file (all rules combined)'
    )

    args = parser.parse_args()

    downloader = YaraRuleDownloader(args.output_dir)

    # Download all rules
    downloader.download_all()

    # Create master rule file
    if args.create_master:
        downloader.create_master_rule()

    logger.info("\n" + "="*80)
    logger.info("✅ YARA rule download complete!")
    logger.info("="*80)
    logger.info(f"\nNext steps:")
    logger.info(f"1. Review rules in: {downloader.curated_dir}")
    logger.info(f"2. Test compilation: yara -c {downloader.compiled_dir}/master_rules.yar")
    logger.info(f"3. Integrate into Custos malware scanner")


if __name__ == "__main__":
    main()
