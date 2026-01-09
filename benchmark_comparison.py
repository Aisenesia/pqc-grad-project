"""
Comprehensive Benchmark: SIMD vs Non-SIMD Comparison
Generates CSV files for all tables in Chapter 4
"""

import sys
import time
import argparse
import csv
import tracemalloc
from statistics import mean, stdev
import importlib.util
import os

def load_lib_module(lib_path, module_name):
    """Dynamically load a lib.py file"""
    spec = importlib.util.spec_from_file_location(module_name, lib_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def benchmark_ecc_keygen(lib):
    """Benchmark ECC key generation"""
    tracemalloc.start()
    start = time.perf_counter()
    
    curve = lib.secp256k1()
    private_key = lib.generate_private_key(curve)
    public_key = lib.derive_public_key(curve, private_key)
    
    elapsed = (time.perf_counter() - start) * 1000  # ms
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return elapsed, peak / (1024 * 1024)  # ms, MB

def benchmark_ecc_exchange(lib):
    """Benchmark ECC key exchange"""
    # Setup
    curve = lib.secp256k1()
    alice_priv = lib.generate_private_key(curve)
    alice_pub = lib.derive_public_key(curve, alice_priv)
    bob_priv = lib.generate_private_key(curve)
    bob_pub = lib.derive_public_key(curve, bob_priv)
    
    tracemalloc.start()
    start = time.perf_counter()
    
    shared_secret_point = lib.derive_shared_secret(curve, alice_priv, bob_pub)
    shared_key = lib.point_to_shared_key(shared_secret_point)
    
    elapsed = (time.perf_counter() - start) * 1000  # ms
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return elapsed, peak / (1024 * 1024)  # ms, MB

def benchmark_kyber_keygen(lib, k):
    """Benchmark Kyber key generation"""
    # Get appropriate params based on k value
    if k == 2:
        params = lib.kyber512_params()
    elif k == 3:
        params = lib.kyber768_params()
    elif k == 4:
        params = lib.kyber1024_params()
    else:
        raise ValueError(f"Invalid k value: {k}")
    
    tracemalloc.start()
    start = time.perf_counter()
    
    pk, sk = lib.kyber_keygen(params)
    
    elapsed = (time.perf_counter() - start) * 1000  # ms
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return elapsed, peak / (1024 * 1024), len(pk), len(sk)  # ms, MB, sizes

def benchmark_kyber_encaps(lib, k):
    """Benchmark Kyber encapsulation"""
    # Get appropriate params based on k value
    if k == 2:
        params = lib.kyber512_params()
    elif k == 3:
        params = lib.kyber768_params()
    elif k == 4:
        params = lib.kyber1024_params()
    else:
        raise ValueError(f"Invalid k value: {k}")
    
    # Setup
    pk, sk = lib.kyber_keygen(params)
    
    tracemalloc.start()
    start = time.perf_counter()
    
    shared_secret, ciphertext = lib.kyber_encapsulate(pk, params)
    
    elapsed = (time.perf_counter() - start) * 1000  # ms
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return elapsed, peak / (1024 * 1024), len(ciphertext)  # ms, MB, ct size

def run_benchmarks(lib, n_runs):
    """Run all benchmarks n times and return averaged results"""
    results = {
        'ecc_keygen': {'time': [], 'memory': []},
        'ecc_exchange': {'time': [], 'memory': []},
        'kyber512_keygen': {'time': [], 'memory': [], 'pk_size': None, 'sk_size': None},
        'kyber512_encaps': {'time': [], 'memory': [], 'ct_size': None},
        'kyber768_keygen': {'time': [], 'memory': [], 'pk_size': None, 'sk_size': None},
        'kyber768_encaps': {'time': [], 'memory': [], 'ct_size': None},
        'kyber1024_keygen': {'time': [], 'memory': [], 'pk_size': None, 'sk_size': None},
        'kyber1024_encaps': {'time': [], 'memory': [], 'ct_size': None},
    }
    
    print(f"Running {n_runs} iterations...")
    
    for i in range(n_runs):
        print(f"  Run {i+1}/{n_runs}...", end='\r')
        
        # ECC benchmarks
        t, m = benchmark_ecc_keygen(lib)
        results['ecc_keygen']['time'].append(t)
        results['ecc_keygen']['memory'].append(m)
        
        t, m = benchmark_ecc_exchange(lib)
        results['ecc_exchange']['time'].append(t)
        results['ecc_exchange']['memory'].append(m)
        
        # Kyber-512
        t, m, pk_size, sk_size = benchmark_kyber_keygen(lib, 2)
        results['kyber512_keygen']['time'].append(t)
        results['kyber512_keygen']['memory'].append(m)
        results['kyber512_keygen']['pk_size'] = pk_size
        results['kyber512_keygen']['sk_size'] = sk_size
        
        t, m, ct_size = benchmark_kyber_encaps(lib, 2)
        results['kyber512_encaps']['time'].append(t)
        results['kyber512_encaps']['memory'].append(m)
        results['kyber512_encaps']['ct_size'] = ct_size
        
        # Kyber-768
        t, m, pk_size, sk_size = benchmark_kyber_keygen(lib, 3)
        results['kyber768_keygen']['time'].append(t)
        results['kyber768_keygen']['memory'].append(m)
        results['kyber768_keygen']['pk_size'] = pk_size
        results['kyber768_keygen']['sk_size'] = sk_size
        
        t, m, ct_size = benchmark_kyber_encaps(lib, 3)
        results['kyber768_encaps']['time'].append(t)
        results['kyber768_encaps']['memory'].append(m)
        results['kyber768_encaps']['ct_size'] = ct_size
        
        # Kyber-1024
        t, m, pk_size, sk_size = benchmark_kyber_keygen(lib, 4)
        results['kyber1024_keygen']['time'].append(t)
        results['kyber1024_keygen']['memory'].append(m)
        results['kyber1024_keygen']['pk_size'] = pk_size
        results['kyber1024_keygen']['sk_size'] = sk_size
        
        t, m, ct_size = benchmark_kyber_encaps(lib, 4)
        results['kyber1024_encaps']['time'].append(t)
        results['kyber1024_encaps']['memory'].append(m)
        results['kyber1024_encaps']['ct_size'] = ct_size
    
    print()  # New line after progress
    
    # Calculate averages
    averaged = {}
    for key, data in results.items():
        averaged[key] = {
            'time_mean': mean(data['time']),
            'time_std': stdev(data['time']) if len(data['time']) > 1 else 0,
            'memory_mean': mean(data['memory']),
            'memory_std': stdev(data['memory']) if len(data['memory']) > 1 else 0,
        }
        if 'pk_size' in data and data['pk_size'] is not None:
            averaged[key]['pk_size'] = data['pk_size']
            averaged[key]['sk_size'] = data['sk_size']
        if 'ct_size' in data and data['ct_size'] is not None:
            averaged[key]['ct_size'] = data['ct_size']
    
    return averaged

def write_execution_time_table(simd_results, no_simd_results, output_dir):
    """Table: Mean Execution Time (milliseconds)"""
    filename = os.path.join(output_dir, 'table_execution_time.csv')
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Algorithm', 'Key Generation (SIMD)', 'Exchange/Encapsulation (SIMD)', 
                        'Key Generation (No SIMD)', 'Exchange/Encapsulation (No SIMD)'])
        
        writer.writerow(['ECC (secp256k1)', 
                        f"{simd_results['ecc_keygen']['time_mean']:.2f}",
                        f"{simd_results['ecc_exchange']['time_mean']:.2f}",
                        f"{no_simd_results['ecc_keygen']['time_mean']:.2f}",
                        f"{no_simd_results['ecc_exchange']['time_mean']:.2f}"])
        
        writer.writerow(['Kyber-512',
                        f"{simd_results['kyber512_keygen']['time_mean']:.2f}",
                        f"{simd_results['kyber512_encaps']['time_mean']:.2f}",
                        f"{no_simd_results['kyber512_keygen']['time_mean']:.2f}",
                        f"{no_simd_results['kyber512_encaps']['time_mean']:.2f}"])
        
        writer.writerow(['Kyber-768',
                        f"{simd_results['kyber768_keygen']['time_mean']:.2f}",
                        f"{simd_results['kyber768_encaps']['time_mean']:.2f}",
                        f"{no_simd_results['kyber768_keygen']['time_mean']:.2f}",
                        f"{no_simd_results['kyber768_encaps']['time_mean']:.2f}"])
        
        writer.writerow(['Kyber-1024',
                        f"{simd_results['kyber1024_keygen']['time_mean']:.2f}",
                        f"{simd_results['kyber1024_encaps']['time_mean']:.2f}",
                        f"{no_simd_results['kyber1024_keygen']['time_mean']:.2f}",
                        f"{no_simd_results['kyber1024_encaps']['time_mean']:.2f}"])
    
    print(f"Written: {filename}")

def write_slowdown_table(simd_results, no_simd_results, output_dir):
    """Table: Slowdown Factor Relative to ECC"""
    filename = os.path.join(output_dir, 'table_slowdown_factor.csv')
    
    ecc_keygen_simd = simd_results['ecc_keygen']['time_mean']
    ecc_encaps_simd = simd_results['ecc_exchange']['time_mean']
    ecc_keygen_no_simd = no_simd_results['ecc_keygen']['time_mean']
    ecc_encaps_no_simd = no_simd_results['ecc_exchange']['time_mean']
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Algorithm', 'Key Generation (SIMD)', 'Encapsulation (SIMD)',
                        'Key Generation (No SIMD)', 'Encapsulation (No SIMD)'])
        
        writer.writerow(['ECC (baseline)', '1.00x', '1.00x', '1.00x', '1.00x'])
        
        writer.writerow(['Kyber-512',
                        f"{simd_results['kyber512_keygen']['time_mean']/ecc_keygen_simd:.2f}x",
                        f"{simd_results['kyber512_encaps']['time_mean']/ecc_encaps_simd:.2f}x",
                        f"{no_simd_results['kyber512_keygen']['time_mean']/ecc_keygen_no_simd:.2f}x",
                        f"{no_simd_results['kyber512_encaps']['time_mean']/ecc_encaps_no_simd:.2f}x"])
        
        writer.writerow(['Kyber-768',
                        f"{simd_results['kyber768_keygen']['time_mean']/ecc_keygen_simd:.2f}x",
                        f"{simd_results['kyber768_encaps']['time_mean']/ecc_encaps_simd:.2f}x",
                        f"{no_simd_results['kyber768_keygen']['time_mean']/ecc_keygen_no_simd:.2f}x",
                        f"{no_simd_results['kyber768_encaps']['time_mean']/ecc_encaps_no_simd:.2f}x"])
        
        writer.writerow(['Kyber-1024',
                        f"{simd_results['kyber1024_keygen']['time_mean']/ecc_keygen_simd:.2f}x",
                        f"{simd_results['kyber1024_encaps']['time_mean']/ecc_encaps_simd:.2f}x",
                        f"{no_simd_results['kyber1024_keygen']['time_mean']/ecc_keygen_no_simd:.2f}x",
                        f"{no_simd_results['kyber1024_encaps']['time_mean']/ecc_encaps_no_simd:.2f}x"])
    
    print(f"Written: {filename}")

def write_memory_table(simd_results, no_simd_results, output_dir):
    """Table: Peak Memory Usage (MB)"""
    filename = os.path.join(output_dir, 'table_memory_usage.csv')
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Algorithm', 'Key Generation (SIMD)', 'Exchange/Encapsulation (SIMD)',
                        'Key Generation (No SIMD)', 'Exchange/Encapsulation (No SIMD)'])
        
        writer.writerow(['ECC',
                        f"{simd_results['ecc_keygen']['memory_mean']:.2f}",
                        f"{simd_results['ecc_exchange']['memory_mean']:.2f}",
                        f"{no_simd_results['ecc_keygen']['memory_mean']:.2f}",
                        f"{no_simd_results['ecc_exchange']['memory_mean']:.2f}"])
        
        writer.writerow(['Kyber-512',
                        f"{simd_results['kyber512_keygen']['memory_mean']:.2f}",
                        f"{simd_results['kyber512_encaps']['memory_mean']:.2f}",
                        f"{no_simd_results['kyber512_keygen']['memory_mean']:.2f}",
                        f"{no_simd_results['kyber512_encaps']['memory_mean']:.2f}"])
        
        writer.writerow(['Kyber-768',
                        f"{simd_results['kyber768_keygen']['memory_mean']:.2f}",
                        f"{simd_results['kyber768_encaps']['memory_mean']:.2f}",
                        f"{no_simd_results['kyber768_keygen']['memory_mean']:.2f}",
                        f"{no_simd_results['kyber768_encaps']['memory_mean']:.2f}"])
        
        writer.writerow(['Kyber-1024',
                        f"{simd_results['kyber1024_keygen']['memory_mean']:.2f}",
                        f"{simd_results['kyber1024_encaps']['memory_mean']:.2f}",
                        f"{no_simd_results['kyber1024_keygen']['memory_mean']:.2f}",
                        f"{no_simd_results['kyber1024_encaps']['memory_mean']:.2f}"])
    
    print(f"Written: {filename}")

def write_keysize_table(simd_results, output_dir):
    """Table: Key and Ciphertext Sizes (bytes) - doesn't change with SIMD"""
    filename = os.path.join(output_dir, 'table_keysize.csv')
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Algorithm', 'Public Key', 'Ciphertext', 'Total Bandwidth'])
        
        writer.writerow(['ECC (secp256k1)', '33', '33', '66'])
        
        pk512 = simd_results['kyber512_keygen']['pk_size']
        ct512 = simd_results['kyber512_encaps']['ct_size']
        writer.writerow(['Kyber-512', pk512, ct512, pk512 + ct512])
        
        pk768 = simd_results['kyber768_keygen']['pk_size']
        ct768 = simd_results['kyber768_encaps']['ct_size']
        writer.writerow(['Kyber-768', pk768, ct768, pk768 + ct768])
        
        pk1024 = simd_results['kyber1024_keygen']['pk_size']
        ct1024 = simd_results['kyber1024_encaps']['ct_size']
        writer.writerow(['Kyber-1024', pk1024, ct1024, pk1024 + ct1024])
    
    print(f"Written: {filename}")

def write_bandwidth_overhead_table(simd_results, output_dir):
    """Table: Bandwidth Overhead Relative to ECC"""
    filename = os.path.join(output_dir, 'table_bandwidth_overhead.csv')
    
    ecc_total = 66
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Algorithm', 'Total Bytes', 'Overhead Factor'])
        
        writer.writerow(['ECC', ecc_total, '1.0x'])
        
        total512 = simd_results['kyber512_keygen']['pk_size'] + simd_results['kyber512_encaps']['ct_size']
        writer.writerow(['Kyber-512', total512, f"{total512/ecc_total:.1f}x"])
        
        total768 = simd_results['kyber768_keygen']['pk_size'] + simd_results['kyber768_encaps']['ct_size']
        writer.writerow(['Kyber-768', total768, f"{total768/ecc_total:.1f}x"])
        
        total1024 = simd_results['kyber1024_keygen']['pk_size'] + simd_results['kyber1024_encaps']['ct_size']
        writer.writerow(['Kyber-1024', total1024, f"{total1024/ecc_total:.1f}x"])
    
    print(f"Written: {filename}")

def write_speedup_analysis(simd_results, no_simd_results, output_dir):
    """Analysis: SIMD Speedup Factor"""
    filename = os.path.join(output_dir, 'analysis_simd_speedup.csv')
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Algorithm', 'Operation', 'No SIMD (ms)', 'With SIMD (ms)', 'Speedup Factor'])
        
        for algo in ['kyber512', 'kyber768', 'kyber1024']:
            algo_name = f"Kyber-{algo[5:]}"
            
            no_simd_keygen = no_simd_results[f'{algo}_keygen']['time_mean']
            simd_keygen = simd_results[f'{algo}_keygen']['time_mean']
            speedup_keygen = no_simd_keygen / simd_keygen
            
            no_simd_encaps = no_simd_results[f'{algo}_encaps']['time_mean']
            simd_encaps = simd_results[f'{algo}_encaps']['time_mean']
            speedup_encaps = no_simd_encaps / simd_encaps
            
            writer.writerow([algo_name, 'Key Generation', 
                           f"{no_simd_keygen:.2f}", f"{simd_keygen:.2f}", f"{speedup_keygen:.2f}x"])
            writer.writerow([algo_name, 'Encapsulation', 
                           f"{no_simd_encaps:.2f}", f"{simd_encaps:.2f}", f"{speedup_encaps:.2f}x"])
    
    print(f"Written: {filename}")

def main():
    parser = argparse.ArgumentParser(description='Benchmark SIMD vs Non-SIMD Kyber implementations')
    parser.add_argument('simd_lib', help='Path to lib.py with SIMD (uses DLL)')
    parser.add_argument('no_simd_lib', help='Path to pure Python lib.py (no SIMD)')
    parser.add_argument('-n', '--runs', type=int, default=10, help='Number of benchmark runs (default: 10)')
    parser.add_argument('-o', '--output', default='benchmark_results', help='Output directory for CSV files')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    print("="*70)
    print("SIMD vs Non-SIMD Benchmark Comparison")
    print("="*70)
    
    # Load libraries
    print("\nLoading libraries...")
    print(f"  SIMD library: {args.simd_lib}")
    simd_lib = load_lib_module(args.simd_lib, "lib_simd")
    print(f"  Non-SIMD library: {args.no_simd_lib}")
    no_simd_lib = load_lib_module(args.no_simd_lib, "lib_no_simd")
    
    # Run benchmarks
    print("\n" + "="*70)
    print("Benchmarking WITH SIMD (DLL-based)")
    print("="*70)
    simd_results = run_benchmarks(simd_lib, args.runs)
    
    print("\n" + "="*70)
    print("Benchmarking WITHOUT SIMD (Pure Python)")
    print("="*70)
    no_simd_results = run_benchmarks(no_simd_lib, args.runs)
    
    # Write all tables
    print("\n" + "="*70)
    print("Generating CSV Tables")
    print("="*70)
    
    write_execution_time_table(simd_results, no_simd_results, args.output)
    write_slowdown_table(simd_results, no_simd_results, args.output)
    write_memory_table(simd_results, no_simd_results, args.output)
    write_keysize_table(simd_results, args.output)
    write_bandwidth_overhead_table(simd_results, args.output)
    write_speedup_analysis(simd_results, no_simd_results, args.output)
    
    print("\n" + "="*70)
    print("Summary")
    print("="*70)
    
    # Calculate average speedup for Kyber operations
    speedups = []
    for algo in ['kyber512', 'kyber768', 'kyber1024']:
        speedups.append(no_simd_results[f'{algo}_keygen']['time_mean'] / simd_results[f'{algo}_keygen']['time_mean'])
        speedups.append(no_simd_results[f'{algo}_encaps']['time_mean'] / simd_results[f'{algo}_encaps']['time_mean'])
    
    avg_speedup = mean(speedups)
    min_speedup = min(speedups)
    max_speedup = max(speedups)
    
    print(f"\nSIMD Speedup Statistics:")
    print(f"  Average: {avg_speedup:.1f}x")
    print(f"  Range: {min_speedup:.1f}x - {max_speedup:.1f}x")
    print(f"\nAll results saved to: {args.output}/")
    print("="*70)

if __name__ == '__main__':
    main()
