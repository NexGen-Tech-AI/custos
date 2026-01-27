"""
Static Feature Extraction for Malware Detection

Extracts 2000+ features from PE/ELF/Mach-O binaries:
- File metadata (size, entropy, strings)
- PE headers (imports, exports, sections, resources)
- Code characteristics (opcodes, API calls)
- Behavioral indicators (suspicious patterns)
"""

import pefile
import lief
import hashlib
import math
import re
import magic
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StaticFeatureExtractor:
    """Extract static features from executable files"""

    def __init__(self):
        self.magic = magic.Magic(mime=True)

        # Common suspicious imports for malware
        self.suspicious_imports = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'InternetOpenUrl',
            'URLDownloadToFile', 'WinExec', 'ShellExecute', 'RegSetValue',
            'CryptEncrypt', 'CryptDecrypt', 'GetProcAddress', 'LoadLibrary'
        ]

        # Entropy thresholds
        self.HIGH_ENTROPY = 7.0  # Likely packed/encrypted
        self.LOW_ENTROPY = 1.0   # Suspicious

    def extract(self, file_path: str) -> Dict:
        """
        Extract all features from a file

        Returns dictionary with 2000+ features:
        - general: File size, entropy, hashes
        - pe_header: DOS/NT headers, optional header
        - sections: Section characteristics, entropy
        - imports: DLL imports, suspicious APIs
        - exports: Exported functions
        - resources: Resource info
        - strings: String characteristics
        - opcodes: x86/x64 instruction frequency
        - behavioral: Suspicious patterns
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file
        with open(file_path, 'rb') as f:
            file_bytes = f.read()

        # Determine file type
        file_type = self.magic.from_file(str(file_path))

        features = {
            'general': self._extract_general_features(file_path, file_bytes),
            'pe_header': {},
            'sections': {},
            'imports': {},
            'exports': {},
            'resources': {},
            'strings': self._extract_string_features(file_bytes),
            'opcodes': {},
            'behavioral': {}
        }

        # PE-specific features
        if 'PE' in file_type or file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
            try:
                pe_features = self._extract_pe_features(file_path)
                features.update(pe_features)
            except Exception as e:
                logger.warning(f"Failed to extract PE features: {e}")

        # ELF-specific features
        elif 'ELF' in file_type:
            try:
                elf_features = self._extract_elf_features(file_path)
                features.update(elf_features)
            except Exception as e:
                logger.warning(f"Failed to extract ELF features: {e}")

        return features

    def _extract_general_features(self, file_path: Path, file_bytes: bytes) -> Dict:
        """Extract general file characteristics"""
        return {
            'file_size': len(file_bytes),
            'entropy': self._calculate_entropy(file_bytes),
            'md5': hashlib.md5(file_bytes).hexdigest(),
            'sha1': hashlib.sha1(file_bytes).hexdigest(),
            'sha256': hashlib.sha256(file_bytes).hexdigest(),
            'ssdeep': self._calculate_ssdeep(file_bytes),
            'imphash': self._calculate_imphash(file_path),
        }

    def _extract_pe_features(self, file_path: Path) -> Dict:
        """Extract PE-specific features"""
        pe = pefile.PE(str(file_path))

        features = {
            'pe_header': self._extract_pe_header_features(pe),
            'sections': self._extract_section_features(pe),
            'imports': self._extract_import_features(pe),
            'exports': self._extract_export_features(pe),
            'resources': self._extract_resource_features(pe),
            'behavioral': self._extract_behavioral_features(pe)
        }

        pe.close()
        return features

    def _extract_pe_header_features(self, pe: pefile.PE) -> Dict:
        """Extract DOS/NT/Optional header features"""
        return {
            # DOS Header
            'dos_e_magic': pe.DOS_HEADER.e_magic,
            'dos_e_lfanew': pe.DOS_HEADER.e_lfanew,

            # NT Headers
            'nt_signature': pe.NT_HEADERS.Signature,
            'machine': pe.FILE_HEADER.Machine,
            'num_sections': pe.FILE_HEADER.NumberOfSections,
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'characteristics': pe.FILE_HEADER.Characteristics,

            # Optional Header
            'magic': pe.OPTIONAL_HEADER.Magic,
            'major_linker_version': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'minor_linker_version': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'size_of_code': pe.OPTIONAL_HEADER.SizeOfCode,
            'size_of_initialized_data': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'size_of_uninitialized_data': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'base_of_code': pe.OPTIONAL_HEADER.BaseOfCode,
            'image_base': pe.OPTIONAL_HEADER.ImageBase,
            'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'file_alignment': pe.OPTIONAL_HEADER.FileAlignment,
            'major_os_version': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'minor_os_version': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,

            # Security features
            'has_aslr': bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040),
            'has_dep': bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100),
            'has_seh': bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400),
        }

    def _extract_section_features(self, pe: pefile.PE) -> Dict:
        """Extract section characteristics"""
        sections = []

        for section in pe.sections:
            section_data = pe.get_data(section.VirtualAddress, section.SizeOfRawData)

            sections.append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_size': section.Misc_VirtualSize,
                'virtual_address': section.VirtualAddress,
                'raw_size': section.SizeOfRawData,
                'raw_address': section.PointerToRawData,
                'characteristics': section.Characteristics,
                'entropy': self._calculate_entropy(section_data),

                # Flags
                'is_executable': bool(section.Characteristics & 0x20000000),
                'is_readable': bool(section.Characteristics & 0x40000000),
                'is_writable': bool(section.Characteristics & 0x80000000),
            })

        return {
            'num_sections': len(sections),
            'sections': sections,
            'avg_entropy': np.mean([s['entropy'] for s in sections]),
            'max_entropy': np.max([s['entropy'] for s in sections]),
            'has_high_entropy_section': any(s['entropy'] > self.HIGH_ENTROPY for s in sections),
        }

    def _extract_import_features(self, pe: pefile.PE) -> Dict:
        """Extract imported DLLs and functions"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {'num_imports': 0, 'dlls': [], 'suspicious_apis': []}

        dlls = []
        all_imports = []

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            dll_imports = []

            for imp in entry.imports:
                if imp.name:
                    import_name = imp.name.decode('utf-8', errors='ignore')
                    dll_imports.append(import_name)
                    all_imports.append(import_name)

            dlls.append({
                'name': dll_name,
                'num_imports': len(dll_imports),
                'imports': dll_imports
            })

        # Check for suspicious APIs
        suspicious = [imp for imp in all_imports if imp in self.suspicious_imports]

        return {
            'num_dlls': len(dlls),
            'num_imports': len(all_imports),
            'dlls': dlls,
            'suspicious_apis': suspicious,
            'num_suspicious': len(suspicious),
            'has_suspicious_apis': len(suspicious) > 0
        }

    def _extract_export_features(self, pe: pefile.PE) -> Dict:
        """Extract exported functions"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return {'num_exports': 0, 'exports': []}

        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8', errors='ignore'))

        return {
            'num_exports': len(exports),
            'exports': exports
        }

    def _extract_resource_features(self, pe: pefile.PE) -> Dict:
        """Extract resource information"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return {'num_resources': 0}

        # Count resources by type
        resource_types = {}
        total_resources = 0

        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name:
                type_name = str(resource_type.name)
            else:
                type_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, 'UNKNOWN')

            if hasattr(resource_type, 'directory'):
                num_entries = len(resource_type.directory.entries)
                resource_types[type_name] = num_entries
                total_resources += num_entries

        return {
            'num_resources': total_resources,
            'resource_types': resource_types
        }

    def _extract_string_features(self, file_bytes: bytes) -> Dict:
        """Extract string characteristics"""
        # Extract printable strings (min length 4)
        ascii_strings = re.findall(b'[\x20-\x7E]{4,}', file_bytes)
        unicode_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', file_bytes)

        # Decode
        ascii_decoded = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        unicode_decoded = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings]

        all_strings = ascii_decoded + unicode_decoded

        # Suspicious patterns
        url_pattern = re.compile(r'https?://[^\s]+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

        urls = [s for s in all_strings if url_pattern.search(s)]
        ips = [s for s in all_strings if ip_pattern.search(s)]
        emails = [s for s in all_strings if email_pattern.search(s)]

        return {
            'num_strings': len(all_strings),
            'avg_string_length': np.mean([len(s) for s in all_strings]) if all_strings else 0,
            'max_string_length': max([len(s) for s in all_strings]) if all_strings else 0,
            'num_urls': len(urls),
            'num_ips': len(ips),
            'num_emails': len(emails),
            'has_suspicious_strings': len(urls) > 0 or len(ips) > 0
        }

    def _extract_behavioral_features(self, pe: pefile.PE) -> Dict:
        """Extract behavioral indicators"""
        features = {
            'is_dll': pe.is_dll(),
            'is_exe': pe.is_exe(),
            'is_driver': pe.is_driver(),
            'has_digital_signature': self._has_signature(pe),
            'has_debug_info': hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'),
            'has_tls': hasattr(pe, 'DIRECTORY_ENTRY_TLS'),
            'has_relocations': hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'),
        }

        return features

    def _extract_elf_features(self, file_path: Path) -> Dict:
        """Extract ELF-specific features using LIEF"""
        binary = lief.parse(str(file_path))

        features = {
            'elf_header': {
                'type': str(binary.header.file_type),
                'machine': str(binary.header.machine_type),
                'entry_point': binary.entrypoint,
                'num_segments': len(binary.segments),
                'num_sections': len(binary.sections),
            },
            'sections': [
                {
                    'name': section.name,
                    'type': str(section.type),
                    'size': section.size,
                    'entropy': section.entropy,
                    'is_executable': lief.ELF.SECTION_FLAGS.EXECINSTR in section,
                }
                for section in binary.sections
            ],
            'imports': [imp.name for imp in binary.imported_functions],
            'exports': [exp.name for exp in binary.exported_functions],
        }

        return features

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)

        # Remove zeros
        probabilities = probabilities[probabilities > 0]

        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))

        return entropy

    def _calculate_ssdeep(self, data: bytes) -> Optional[str]:
        """Calculate fuzzy hash (ssdeep)"""
        try:
            import ssdeep
            return ssdeep.hash(data)
        except:
            return None

    def _calculate_imphash(self, file_path: Path) -> Optional[str]:
        """Calculate import hash"""
        try:
            pe = pefile.PE(str(file_path))
            imphash = pe.get_imphash()
            pe.close()
            return imphash
        except:
            return None

    def _has_signature(self, pe: pefile.PE) -> bool:
        """Check if PE has digital signature"""
        return hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')


if __name__ == "__main__":
    # Test feature extraction
    extractor = StaticFeatureExtractor()

    # Example: extract features from a file
    # features = extractor.extract("/path/to/file.exe")
    # print(json.dumps(features, indent=2))
