"""
Check SIMD optimization status of the compiled library
"""

from lib import get_simd_info, print_simd_info

if __name__ == "__main__":
    print("="*60)
    print("SIMD Optimization Status")
    print("="*60)
    print_simd_info()
    print("="*60)
    
    # Also return as dict for programmatic use
    info = get_simd_info()
    print("\nDetailed info:")
    for key, value in info.items():
        print(f"  {key}: {value}")
