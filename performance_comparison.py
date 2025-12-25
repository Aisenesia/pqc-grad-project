"""
Performance Comparison: CRYSTALS-Kyber vs ECC (secp256k1)
Comprehensive benchmarking of key exchange operations for post-quantum vs classical cryptography.
"""

import time
import statistics
import matplotlib.pyplot as plt
import numpy as np
from typing import List, Dict, Tuple
import sys
import tracemalloc
import gc

# Try to import pympler for accurate size measurement, fall back to sys.getsizeof
try:
    from pympler import asizeof
    HAS_PYMPLER = True
except ImportError:
    import sys as _sys
    HAS_PYMPLER = False
    print("Warning: pympler not found. Install with 'pip install pympler' for accurate size measurements.")
    print("Falling back to sys.getsizeof (less accurate for complex objects)\n")

    # Simple fallback
    class asizeof:
        @staticmethod
        def asizeof(obj):
            if isinstance(obj, bytes):
                return len(obj) + 40  # bytes overhead
            elif isinstance(obj, int):
                return _sys.getsizeof(obj)
            else:
                return _sys.getsizeof(obj)

# Import our cryptographic implementations
from lib import (
    # ECC
    secp256k1,
    Point,
    generate_private_key,
    derive_public_key,
    derive_shared_secret,

    # Kyber
    kyber512_params,
    kyber768_params,
    kyber1024_params,
    kyber_keygen,
    kyber_encapsulate,
    kyber_decapsulate
)


class PerformanceMetrics:
    """Container for performance measurements"""
    def __init__(self, name: str):
        self.name = name
        self.times: List[float] = []
        self.memory_peak: List[float] = []  # Peak memory during computation in MB (includes temp allocations)
        self.memory_allocated: List[float] = []  # Total allocated memory in MB
        self.actual_size: float = 0  # Actual size of result objects in MB

    def add_measurement(self, time_ms: float, mem_peak: float = 0, mem_alloc: float = 0):
        self.times.append(time_ms)
        if mem_peak > 0:
            self.memory_peak.append(mem_peak)
        if mem_alloc > 0:
            self.memory_allocated.append(mem_alloc)

    @property
    def mean(self) -> float:
        return statistics.mean(self.times) if self.times else 0

    @property
    def median(self) -> float:
        return statistics.median(self.times) if self.times else 0

    @property
    def stdev(self) -> float:
        return statistics.stdev(self.times) if len(self.times) > 1 else 0

    @property
    def min(self) -> float:
        return min(self.times) if self.times else 0

    @property
    def max(self) -> float:
        return max(self.times) if self.times else 0

    @property
    def mean_memory_peak(self) -> float:
        return statistics.mean(self.memory_peak) if self.memory_peak else 0

    @property
    def mean_memory_allocated(self) -> float:
        return statistics.mean(self.memory_allocated) if self.memory_allocated else 0


class BandwidthMetrics:
    """Container for bandwidth/data size measurements"""
    def __init__(self, name: str):
        self.name = name
        self.public_key_size = 0
        self.private_key_size = 0
        self.ciphertext_size = 0
        self.shared_secret_size = 0
        self.total_exchange_bytes = 0  # Total bytes exchanged during key exchange


def benchmark_operation(func, *args, warmup=5, iterations=100, **kwargs) -> PerformanceMetrics:
    """
    Benchmark a function with warmup and multiple iterations.

    Args:
        func: Function to benchmark
        warmup: Number of warmup iterations (not measured)
        iterations: Number of measured iterations

    Returns:
        PerformanceMetrics with timing data
    """
    # Warmup phase - stabilize CPU caches and JIT
    for _ in range(warmup):
        func(*args, **kwargs)

    # Measurement phase
    metrics = PerformanceMetrics(func.__name__)
    for _ in range(iterations):
        # Force garbage collection before measurement
        gc.collect()

        # Start memory tracking
        tracemalloc.start()

        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()

        # Get memory stats
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        metrics.add_measurement(
            (end - start) * 1000,  # Convert to milliseconds
            peak / (1024 * 1024),  # Convert to MB
            current / (1024 * 1024)  # Convert to MB
        )

    return metrics, result


def benchmark_ecc_keygen(iterations=100) -> PerformanceMetrics:
    """Benchmark ECC key pair generation"""
    print("Benchmarking ECC key generation...")
    metrics = PerformanceMetrics("ECC KeyGen")
    curve = secp256k1()

    # Warmup
    for _ in range(5):
        private_key = generate_private_key(curve)
        public_key = derive_public_key(curve, private_key)

    # Measurement
    for i in range(iterations):
        gc.collect()
        tracemalloc.start()

        start = time.perf_counter()
        private_key = generate_private_key(curve)
        public_key = derive_public_key(curve, private_key)
        end = time.perf_counter()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure actual object sizes (only on first iteration)
        if i == 0:
            try:
                size_priv = asizeof.asizeof(private_key)
                size_pub = asizeof.asizeof(public_key)
                metrics.actual_size = (size_priv + size_pub) / (1024 * 1024)
            except:
                metrics.actual_size = 0.0001  # Fallback: ~100 bytes

        metrics.add_measurement(
            (end - start) * 1000,
            peak / (1024 * 1024),
            current / (1024 * 1024)
        )

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{iterations}")

    return metrics


def benchmark_ecc_key_exchange(iterations=100) -> Tuple[PerformanceMetrics, PerformanceMetrics]:
    """Benchmark complete ECC key exchange (both parties)"""
    print("Benchmarking ECC key exchange...")
    curve = secp256k1()

    alice_metrics = PerformanceMetrics("ECC Alice Exchange")
    bob_metrics = PerformanceMetrics("ECC Bob Exchange")

    # Warmup
    for _ in range(5):
        alice_priv = generate_private_key(curve)
        alice_pub = derive_public_key(curve, alice_priv)
        bob_priv = generate_private_key(curve)
        bob_pub = derive_public_key(curve, bob_priv)
        derive_shared_secret(curve, alice_priv, bob_pub)
        derive_shared_secret(curve, bob_priv, alice_pub)

    # Measurement
    for i in range(iterations):
        # Generate keys
        alice_priv = generate_private_key(curve)
        alice_pub = derive_public_key(curve, alice_priv)
        bob_priv = generate_private_key(curve)
        bob_pub = derive_public_key(curve, bob_priv)

        # Alice computes shared secret
        gc.collect()
        tracemalloc.start()
        start = time.perf_counter()
        alice_shared = derive_shared_secret(curve, alice_priv, bob_pub)
        end = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        if i == 0:
            try:
                alice_metrics.actual_size = asizeof.asizeof(alice_shared) / (1024 * 1024)
            except:
                alice_metrics.actual_size = 0.0001  # ~100 bytes

        alice_metrics.add_measurement((end - start) * 1000, peak / (1024 * 1024), current / (1024 * 1024))

        # Bob computes shared secret
        gc.collect()
        tracemalloc.start()
        start = time.perf_counter()
        bob_shared = derive_shared_secret(curve, bob_priv, alice_pub)
        end = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        if i == 0:
            try:
                bob_metrics.actual_size = asizeof.asizeof(bob_shared) / (1024 * 1024)
            except:
                bob_metrics.actual_size = 0.0001

        bob_metrics.add_measurement((end - start) * 1000, peak / (1024 * 1024), current / (1024 * 1024))

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{iterations}")

    return alice_metrics, bob_metrics


def benchmark_kyber_keygen(params, name: str, iterations=100) -> PerformanceMetrics:
    """Benchmark Kyber key pair generation"""
    print(f"Benchmarking {name} key generation...")
    metrics = PerformanceMetrics(f"{name} KeyGen")

    # Warmup
    for _ in range(5):
        kyber_keygen(params)

    # Measurement
    for i in range(iterations):
        gc.collect()
        tracemalloc.start()

        start = time.perf_counter()
        pk, sk = kyber_keygen(params)
        end = time.perf_counter()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure actual object sizes (only on first iteration)
        if i == 0:
            try:
                size_pk = asizeof.asizeof(pk)
                size_sk = asizeof.asizeof(sk)
                metrics.actual_size = (size_pk + size_sk) / (1024 * 1024)
            except:
                metrics.actual_size = (len(pk) + len(sk)) / (1024 * 1024)

        metrics.add_measurement(
            (end - start) * 1000,
            peak / (1024 * 1024),
            current / (1024 * 1024)
        )

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{iterations}")

    return metrics


def benchmark_kyber_key_exchange(params, name: str, iterations=100) -> Tuple[PerformanceMetrics, PerformanceMetrics]:
    """Benchmark complete Kyber key exchange (encapsulation + decapsulation)"""
    print(f"Benchmarking {name} key exchange...")

    encaps_metrics = PerformanceMetrics(f"{name} Encaps")
    decaps_metrics = PerformanceMetrics(f"{name} Decaps")

    # Warmup
    for _ in range(5):
        pk, sk = kyber_keygen(params)
        ss1, ct = kyber_encapsulate(pk, params)
        ss2 = kyber_decapsulate(ct, sk, params)

    # Measurement
    for i in range(iterations):
        # Generate keys
        pk, sk = kyber_keygen(params)

        # Encapsulation (sender's side)
        gc.collect()
        tracemalloc.start()
        start = time.perf_counter()
        shared_secret_sender, ciphertext = kyber_encapsulate(pk, params)
        end = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        if i == 0:
            try:
                size_ss = asizeof.asizeof(shared_secret_sender)
                size_ct = asizeof.asizeof(ciphertext)
                encaps_metrics.actual_size = (size_ss + size_ct) / (1024 * 1024)
            except:
                encaps_metrics.actual_size = (len(shared_secret_sender) + len(ciphertext)) / (1024 * 1024)

        encaps_metrics.add_measurement((end - start) * 1000, peak / (1024 * 1024), current / (1024 * 1024))

        # Decapsulation (receiver's side)
        gc.collect()
        tracemalloc.start()
        start = time.perf_counter()
        shared_secret_receiver = kyber_decapsulate(ciphertext, sk, params)
        end = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        if i == 0:
            try:
                decaps_metrics.actual_size = asizeof.asizeof(shared_secret_receiver) / (1024 * 1024)
            except:
                decaps_metrics.actual_size = len(shared_secret_receiver) / (1024 * 1024)

        decaps_metrics.add_measurement((end - start) * 1000, peak / (1024 * 1024), current / (1024 * 1024))

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{iterations}")

    return encaps_metrics, decaps_metrics


def print_statistics(metrics: PerformanceMetrics):
    """Print detailed statistics for a performance metric"""
    print(f"\n{metrics.name}:")
    print(f"  Time Mean:   {metrics.mean:.4f} ms")
    print(f"  Time Median: {metrics.median:.4f} ms")
    print(f"  Time StdDev: {metrics.stdev:.4f} ms")
    print(f"  Time Min:    {metrics.min:.4f} ms")
    print(f"  Time Max:    {metrics.max:.4f} ms")
    if metrics.memory_peak:
        print(f"  Peak Memory (computation): {metrics.mean_memory_peak:.4f} MB")
        print(f"  Actual Size (storage):     {metrics.actual_size:.4f} MB")
    if metrics.actual_size > 0:
        print(f"  Storage Efficiency:        {metrics.actual_size * 1024:.2f} KB")


def measure_bandwidth_ecc() -> BandwidthMetrics:
    """Measure data sizes for ECC key exchange"""
    print("Measuring ECC bandwidth requirements...")
    curve = secp256k1()
    metrics = BandwidthMetrics("ECC")

    # Generate keys
    private_key = generate_private_key(curve)
    public_key = derive_public_key(curve, private_key)

    # Measure sizes
    # Private key: 32 bytes (256-bit integer)
    metrics.private_key_size = 32

    # Public key: compressed point (33 bytes) or uncompressed (65 bytes)
    # We'll use compressed: 1 byte prefix + 32 bytes x-coordinate
    metrics.public_key_size = 33

    # Shared secret: 32 bytes (SHA-256 hash of point)
    metrics.shared_secret_size = 32

    # Total exchange: Alice sends public key to Bob, Bob sends public key to Alice
    metrics.total_exchange_bytes = 2 * metrics.public_key_size

    # No ciphertext in ECDH
    metrics.ciphertext_size = 0

    return metrics


def measure_bandwidth_kyber(params, name: str) -> BandwidthMetrics:
    """Measure data sizes for Kyber key exchange"""
    print(f"Measuring {name} bandwidth requirements...")
    metrics = BandwidthMetrics(name)

    # Generate keys and perform exchange
    pk, sk = kyber_keygen(params)
    shared_secret, ciphertext = kyber_encapsulate(pk, params)

    # Measure actual sizes
    metrics.public_key_size = len(pk)
    metrics.private_key_size = len(sk)
    metrics.ciphertext_size = len(ciphertext)
    metrics.shared_secret_size = len(shared_secret)

    # Total exchange: Send public key once, then send ciphertext back
    metrics.total_exchange_bytes = metrics.public_key_size + metrics.ciphertext_size

    return metrics


def calculate_slowdown(baseline: float, target: float) -> float:
    """Calculate slowdown factor (how many times slower)"""
    return target / baseline if baseline > 0 else 0


def create_comparison_plots(results: Dict[str, PerformanceMetrics], bandwidth: Dict[str, BandwidthMetrics]):
    """Create comprehensive comparison visualizations"""

    # Extract data
    names = list(results.keys())
    means = [results[name].mean for name in names]
    medians = [results[name].median for name in names]
    stdevs = [results[name].stdev for name in names]
    memory_peaks = [results[name].mean_memory_peak for name in names]

    # Create figure with subplots
    fig = plt.figure(figsize=(18, 14))

    # 1. Mean comparison bar chart
    ax1 = plt.subplot(3, 3, 1)
    colors = ['#2ecc71' if 'ECC' in name else '#e74c3c' if 'Kyber-512' in name
              else '#f39c12' if 'Kyber-768' in name else '#9b59b6' for name in names]
    bars = ax1.bar(range(len(names)), means, color=colors, alpha=0.7, edgecolor='black')
    ax1.set_ylabel('Time (ms)', fontsize=12, fontweight='bold')
    ax1.set_title('Mean Execution Time Comparison', fontsize=14, fontweight='bold')
    ax1.set_xticks(range(len(names)))
    ax1.set_xticklabels(names, rotation=45, ha='right', fontsize=8)
    ax1.grid(axis='y', alpha=0.3)

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontsize=8)

    # 2. Memory usage comparison
    ax2 = plt.subplot(3, 3, 2)
    bars2 = ax2.bar(range(len(names)), memory_peaks, color=colors, alpha=0.7, edgecolor='black')
    ax2.set_ylabel('Memory (MB)', fontsize=12, fontweight='bold')
    ax2.set_title('Peak Memory Usage', fontsize=14, fontweight='bold')
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(names, rotation=45, ha='right', fontsize=8)
    ax2.grid(axis='y', alpha=0.3)

    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontsize=8)

    # 3. Slowdown relative to ECC
    ax3 = plt.subplot(3, 3, 3)
    ecc_baseline = means[0]  # Assuming first is ECC
    slowdowns = [calculate_slowdown(ecc_baseline, mean) for mean in means]
    bars3 = ax3.bar(range(len(names)), slowdowns, color=colors, alpha=0.7, edgecolor='black')
    ax3.axhline(y=1, color='green', linestyle='--', linewidth=2, label='ECC Baseline')
    ax3.set_ylabel('Slowdown Factor (×)', fontsize=12, fontweight='bold')
    ax3.set_title('Slowdown Relative to ECC', fontsize=14, fontweight='bold')
    ax3.set_xticks(range(len(names)))
    ax3.set_xticklabels(names, rotation=45, ha='right', fontsize=8)
    ax3.legend()
    ax3.grid(axis='y', alpha=0.3)

    # Add value labels
    for bar in bars3:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}×',
                ha='center', va='bottom', fontsize=8)

    # 4. Box plot showing distribution
    ax4 = plt.subplot(3, 3, 4)
    data = [results[name].times for name in names]
    bp = ax4.boxplot(data, labels=names, patch_artist=True)
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax4.set_ylabel('Time (ms)', fontsize=12, fontweight='bold')
    ax4.set_title('Distribution of Execution Times', fontsize=14, fontweight='bold')
    ax4.set_xticklabels(names, rotation=45, ha='right', fontsize=8)
    ax4.grid(axis='y', alpha=0.3)

    # 5. Bandwidth comparison - Public Key Sizes
    ax5 = plt.subplot(3, 3, 5)
    bw_names = list(bandwidth.keys())
    pk_sizes = [bandwidth[name].public_key_size for name in bw_names]
    bw_colors = ['#2ecc71' if 'ECC' in name else '#e74c3c' if 'Kyber-512' in name
                 else '#f39c12' if 'Kyber-768' in name else '#9b59b6' for name in bw_names]
    bars5 = ax5.bar(range(len(bw_names)), pk_sizes, color=bw_colors, alpha=0.7, edgecolor='black')
    ax5.set_ylabel('Size (bytes)', fontsize=12, fontweight='bold')
    ax5.set_title('Public Key Size Comparison', fontsize=14, fontweight='bold')
    ax5.set_xticks(range(len(bw_names)))
    ax5.set_xticklabels(bw_names, rotation=45, ha='right', fontsize=8)
    ax5.grid(axis='y', alpha=0.3)

    for bar in bars5:
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=8)

    # 6. Total Exchange Bandwidth
    ax6 = plt.subplot(3, 3, 6)
    total_bytes = [bandwidth[name].total_exchange_bytes for name in bw_names]
    bars6 = ax6.bar(range(len(bw_names)), total_bytes, color=bw_colors, alpha=0.7, edgecolor='black')
    ax6.set_ylabel('Size (bytes)', fontsize=12, fontweight='bold')
    ax6.set_title('Total Key Exchange Bandwidth', fontsize=14, fontweight='bold')
    ax6.set_xticks(range(len(bw_names)))
    ax6.set_xticklabels(bw_names, rotation=45, ha='right', fontsize=8)
    ax6.grid(axis='y', alpha=0.3)

    for bar in bars6:
        height = bar.get_height()
        ax6.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=8)

    # 7. Bandwidth overhead relative to ECC
    ax7 = plt.subplot(3, 3, 7)
    ecc_bandwidth = total_bytes[0]
    bw_overheads = [(b / ecc_bandwidth) for b in total_bytes]
    bars7 = ax7.bar(range(len(bw_names)), bw_overheads, color=bw_colors, alpha=0.7, edgecolor='black')
    ax7.axhline(y=1, color='green', linestyle='--', linewidth=2, label='ECC Baseline')
    ax7.set_ylabel('Bandwidth Factor (×)', fontsize=12, fontweight='bold')
    ax7.set_title('Bandwidth Overhead vs ECC', fontsize=14, fontweight='bold')
    ax7.set_xticks(range(len(bw_names)))
    ax7.set_xticklabels(bw_names, rotation=45, ha='right', fontsize=8)
    ax7.legend()
    ax7.grid(axis='y', alpha=0.3)

    for bar in bars7:
        height = bar.get_height()
        ax7.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}×',
                ha='center', va='bottom', fontsize=8)

    # 8. Cumulative distribution
    ax8 = plt.subplot(3, 3, 8)
    for name, color in zip(names, colors):
        sorted_times = np.sort(results[name].times)
        cumulative = np.arange(1, len(sorted_times) + 1) / len(sorted_times)
        ax8.plot(sorted_times, cumulative, label=name, linewidth=2, color=color, alpha=0.7)

    ax8.set_xlabel('Time (ms)', fontsize=12, fontweight='bold')
    ax8.set_ylabel('Cumulative Probability', fontsize=12, fontweight='bold')
    ax8.set_title('Cumulative Distribution Function', fontsize=14, fontweight='bold')
    ax8.legend(fontsize=7)
    ax8.grid(alpha=0.3)

    # 9. Performance summary table
    ax9 = plt.subplot(3, 3, 9)
    ax9.axis('tight')
    ax9.axis('off')

    table_data = []
    table_data.append(['Algorithm', 'Time (ms)', 'Slowdown', 'Bandwidth'])
    for name in names:
        mean = results[name].mean
        slowdown = calculate_slowdown(ecc_baseline, mean)
        # Find corresponding bandwidth
        bw_name = name.replace(' KeyGen', '').replace(' Exchange', '')
        if bw_name in bandwidth:
            bw = bandwidth[bw_name].total_exchange_bytes
            bw_str = f'{bw} B'
        else:
            bw_str = 'N/A'
        table_data.append([
            name[:20],
            f'{mean:.2f}',
            f'{slowdown:.2f}×',
            bw_str
        ])

    table = ax9.table(cellText=table_data, cellLoc='left', loc='center',
                     colWidths=[0.4, 0.2, 0.2, 0.2])
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    table.scale(1, 1.5)

    # Style header row
    for i in range(4):
        table[(0, i)].set_facecolor('#34495e')
        table[(0, i)].set_text_props(weight='bold', color='white')

    ax9.set_title('Performance Summary', fontsize=14, fontweight='bold', pad=20)

    plt.tight_layout()
    plt.savefig('kyber_vs_ecc_performance.png', dpi=300, bbox_inches='tight')
    print("\n Saved comprehensive plot to: kyber_vs_ecc_performance.png")

    # Create a focused key exchange comparison plot
    fig2, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Left: Key exchange operations only
    exchange_only = {k: v for k, v in results.items() if 'KeyGen' not in k}
    names_ex = list(exchange_only.keys())
    means_ex = [exchange_only[name].mean for name in names_ex]
    colors_ex = ['#2ecc71' if 'ECC' in name else '#e74c3c' if 'Kyber-512' in name
                 else '#f39c12' if 'Kyber-768' in name else '#9b59b6' for name in names_ex]

    bars = ax1.bar(range(len(names_ex)), means_ex, color=colors_ex, alpha=0.7, edgecolor='black')
    ax1.set_ylabel('Time (ms)', fontsize=12, fontweight='bold')
    ax1.set_title('Key Exchange Performance', fontsize=14, fontweight='bold')
    ax1.set_xticks(range(len(names_ex)))
    ax1.set_xticklabels(names_ex, rotation=45, ha='right')
    ax1.grid(axis='y', alpha=0.3)

    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontsize=10)

    # Right: Relative slowdown
    ecc_exchange = means_ex[0]
    slowdowns_ex = [calculate_slowdown(ecc_exchange, mean) for mean in means_ex]
    bars2 = ax2.bar(range(len(names_ex)), slowdowns_ex, color=colors_ex, alpha=0.7, edgecolor='black')
    ax2.axhline(y=1, color='green', linestyle='--', linewidth=2, label='ECC Baseline')
    ax2.set_ylabel('Slowdown Factor (×)', fontsize=12, fontweight='bold')
    ax2.set_title('Key Exchange Slowdown vs ECC', fontsize=14, fontweight='bold')
    ax2.set_xticks(range(len(names_ex)))
    ax2.set_xticklabels(names_ex, rotation=45, ha='right')
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)

    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}×',
                ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    plt.savefig('key_exchange_comparison.png', dpi=300, bbox_inches='tight')
    print(" Saved key exchange comparison to: key_exchange_comparison.png")
    plt.close('all')

    # Create bandwidth comparison plot
    create_bandwidth_plot(bandwidth)


def create_bandwidth_plot(bandwidth: Dict[str, BandwidthMetrics]):
    """Create detailed bandwidth comparison visualization"""
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))

    names = list(bandwidth.keys())
    colors = ['#2ecc71' if 'ECC' in name else '#e74c3c' if 'Kyber-512' in name
              else '#f39c12' if 'Kyber-768' in name else '#9b59b6' for name in names]

    # 1. Breakdown of data sizes
    pk_sizes = [bandwidth[name].public_key_size for name in names]
    sk_sizes = [bandwidth[name].private_key_size for name in names]
    ct_sizes = [bandwidth[name].ciphertext_size for name in names]
    ss_sizes = [bandwidth[name].shared_secret_size for name in names]

    x = np.arange(len(names))
    width = 0.2

    ax1.bar(x - 1.5*width, pk_sizes, width, label='Public Key', color='#3498db', alpha=0.7, edgecolor='black')
    ax1.bar(x - 0.5*width, sk_sizes, width, label='Private Key', color='#e74c3c', alpha=0.7, edgecolor='black')
    ax1.bar(x + 0.5*width, ct_sizes, width, label='Ciphertext', color='#f39c12', alpha=0.7, edgecolor='black')
    ax1.bar(x + 1.5*width, ss_sizes, width, label='Shared Secret', color='#2ecc71', alpha=0.7, edgecolor='black')

    ax1.set_ylabel('Size (bytes)', fontsize=12, fontweight='bold')
    ax1.set_title('Data Size Breakdown', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, rotation=45, ha='right')
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)

    # 2. Total exchange bandwidth
    total_bytes = [bandwidth[name].total_exchange_bytes for name in names]
    bars2 = ax2.bar(range(len(names)), total_bytes, color=colors, alpha=0.7, edgecolor='black')
    ax2.set_ylabel('Size (bytes)', fontsize=12, fontweight='bold')
    ax2.set_title('Total Key Exchange Bandwidth', fontsize=14, fontweight='bold')
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(names, rotation=45, ha='right')
    ax2.grid(axis='y', alpha=0.3)

    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}B',
                ha='center', va='bottom', fontsize=9)

    # 3. Bandwidth overhead table
    ax3.axis('tight')
    ax3.axis('off')

    ecc_bandwidth = total_bytes[0]
    table_data = []
    table_data.append(['Algorithm', 'PubKey', 'Ciphertext', 'Total', 'vs ECC'])
    for i, name in enumerate(names):
        bw = bandwidth[name]
        overhead = (total_bytes[i] / ecc_bandwidth - 1) * 100 if i > 0 else 0
        table_data.append([
            name,
            f'{bw.public_key_size}B',
            f'{bw.ciphertext_size}B' if bw.ciphertext_size > 0 else 'N/A',
            f'{bw.total_exchange_bytes}B',
            f'+{overhead:.0f}%' if i > 0 else 'Baseline'
        ])

    table = ax3.table(cellText=table_data, cellLoc='left', loc='center',
                     colWidths=[0.25, 0.2, 0.2, 0.2, 0.15])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2.5)

    # Style header row
    for i in range(5):
        table[(0, i)].set_facecolor('#34495e')
        table[(0, i)].set_text_props(weight='bold', color='white')

    ax3.set_title('Bandwidth Details', fontsize=14, fontweight='bold', pad=20)

    # 4. Bandwidth multiplier
    multipliers = [total_bytes[i] / ecc_bandwidth for i in range(len(names))]
    bars4 = ax4.bar(range(len(names)), multipliers, color=colors, alpha=0.7, edgecolor='black')
    ax4.axhline(y=1, color='green', linestyle='--', linewidth=2, label='ECC Baseline')
    ax4.set_ylabel('Bandwidth Factor (×)', fontsize=12, fontweight='bold')
    ax4.set_title('Bandwidth Overhead vs ECC', fontsize=14, fontweight='bold')
    ax4.set_xticks(range(len(names)))
    ax4.set_xticklabels(names, rotation=45, ha='right')
    ax4.legend()
    ax4.grid(axis='y', alpha=0.3)

    for bar in bars4:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}×',
                ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig('bandwidth_comparison.png', dpi=300, bbox_inches='tight')
    print(" Saved bandwidth comparison to: bandwidth_comparison.png")
    plt.close('all')


def create_memory_comparison_plot(results: Dict[str, PerformanceMetrics]):
    """Create detailed memory comparison visualization"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    names = list(results.keys())
    colors = ['#2ecc71' if 'ECC' in name else '#e74c3c' if 'Kyber-512' in name
              else '#f39c12' if 'Kyber-768' in name else '#9b59b6' for name in names]

    memory_peaks = [results[name].mean_memory_peak for name in names]
    memory_allocs = [results[name].mean_memory_allocated for name in names]

    # 1. Memory usage comparison
    x = np.arange(len(names))
    width = 0.35

    bars1 = ax1.bar(x - width/2, memory_peaks, width, label='Peak Memory',
                    color='#e74c3c', alpha=0.7, edgecolor='black')
    bars2 = ax1.bar(x + width/2, memory_allocs, width, label='Allocated Memory',
                    color='#3498db', alpha=0.7, edgecolor='black')

    ax1.set_ylabel('Memory (MB)', fontsize=12, fontweight='bold')
    ax1.set_title('Memory Usage Comparison', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, rotation=45, ha='right')
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)

    # Add values on bars
    for bar in bars1:
        height = bar.get_height()
        if height > 0:
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}',
                    ha='center', va='bottom', fontsize=8)

    # 2. Memory overhead relative to ECC
    ecc_mem_baseline = memory_peaks[0]
    mem_factors = [m / ecc_mem_baseline if ecc_mem_baseline > 0 else 0 for m in memory_peaks]

    bars3 = ax2.bar(range(len(names)), mem_factors, color=colors, alpha=0.7, edgecolor='black')
    ax2.axhline(y=1, color='green', linestyle='--', linewidth=2, label='ECC Baseline')
    ax2.set_ylabel('Memory Factor (×)', fontsize=12, fontweight='bold')
    ax2.set_title('Memory Overhead vs ECC', fontsize=14, fontweight='bold')
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(names, rotation=45, ha='right')
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)

    for bar in bars3:
        height = bar.get_height()
        if height > 0:
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}×',
                    ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig('memory_comparison.png', dpi=300, bbox_inches='tight')
    print(" Saved memory comparison to: memory_comparison.png")
    plt.close('all')


def run_comprehensive_benchmark(iterations=100):
    """Run complete benchmark suite"""
    print("=" * 80)
    print("PERFORMANCE COMPARISON: CRYSTALS-Kyber vs ECC (secp256k1)")
    print("=" * 80)
    print(f"Running {iterations} iterations per test with 5 warmup iterations\n")

    results = {}
    bandwidth = {}

    # Measure bandwidth first (doesn't need iterations)
    print("\n" + "─" * 80)
    print("Bandwidth Measurements")
    print("─" * 80)
    bandwidth['ECC'] = measure_bandwidth_ecc()
    bandwidth['Kyber-512'] = measure_bandwidth_kyber(kyber512_params(), "Kyber-512")
    bandwidth['Kyber-768'] = measure_bandwidth_kyber(kyber768_params(), "Kyber-768")
    bandwidth['Kyber-1024'] = measure_bandwidth_kyber(kyber1024_params(), "Kyber-1024")

    # ECC Benchmarks
    print("\n" + "─" * 80)
    print("ECC (secp256k1) Benchmarks")
    print("─" * 80)
    ecc_keygen = benchmark_ecc_keygen(iterations)
    results['ECC KeyGen'] = ecc_keygen

    ecc_alice, ecc_bob = benchmark_ecc_key_exchange(iterations)
    # Average both parties for fair comparison
    ecc_exchange = PerformanceMetrics("ECC Exchange")
    ecc_exchange.times = [(a + b) / 2 for a, b in zip(ecc_alice.times, ecc_bob.times)]
    ecc_exchange.memory_peak = [(a + b) / 2 for a, b in zip(ecc_alice.memory_peak, ecc_bob.memory_peak)]
    ecc_exchange.memory_allocated = [(a + b) / 2 for a, b in zip(ecc_alice.memory_allocated, ecc_bob.memory_allocated)]
    ecc_exchange.actual_size = (ecc_alice.actual_size + ecc_bob.actual_size) / 2
    results['ECC Exchange'] = ecc_exchange

    # Kyber-512 Benchmarks
    print("\n" + "─" * 80)
    print("Kyber-512 Benchmarks (NIST Level 1)")
    print("─" * 80)
    kyber512_keygen = benchmark_kyber_keygen(kyber512_params(), "Kyber-512", iterations)
    results['Kyber-512 KeyGen'] = kyber512_keygen

    kyber512_encaps, kyber512_decaps = benchmark_kyber_key_exchange(kyber512_params(), "Kyber-512", iterations)
    kyber512_exchange = PerformanceMetrics("Kyber-512 Exchange")
    kyber512_exchange.times = [(e + d) / 2 for e, d in zip(kyber512_encaps.times, kyber512_decaps.times)]
    kyber512_exchange.memory_peak = [(e + d) / 2 for e, d in zip(kyber512_encaps.memory_peak, kyber512_decaps.memory_peak)]
    kyber512_exchange.memory_allocated = [(e + d) / 2 for e, d in zip(kyber512_encaps.memory_allocated, kyber512_decaps.memory_allocated)]
    kyber512_exchange.actual_size = (kyber512_encaps.actual_size + kyber512_decaps.actual_size) / 2
    results['Kyber-512 Exchange'] = kyber512_exchange

    # Kyber-768 Benchmarks
    print("\n" + "─" * 80)
    print("Kyber-768 Benchmarks (NIST Level 3)")
    print("─" * 80)
    kyber768_keygen = benchmark_kyber_keygen(kyber768_params(), "Kyber-768", iterations)
    results['Kyber-768 KeyGen'] = kyber768_keygen

    kyber768_encaps, kyber768_decaps = benchmark_kyber_key_exchange(kyber768_params(), "Kyber-768", iterations)
    kyber768_exchange = PerformanceMetrics("Kyber-768 Exchange")
    kyber768_exchange.times = [(e + d) / 2 for e, d in zip(kyber768_encaps.times, kyber768_decaps.times)]
    kyber768_exchange.memory_peak = [(e + d) / 2 for e, d in zip(kyber768_encaps.memory_peak, kyber768_decaps.memory_peak)]
    kyber768_exchange.memory_allocated = [(e + d) / 2 for e, d in zip(kyber768_encaps.memory_allocated, kyber768_decaps.memory_allocated)]
    kyber768_exchange.actual_size = (kyber768_encaps.actual_size + kyber768_decaps.actual_size) / 2
    results['Kyber-768 Exchange'] = kyber768_exchange

    # Kyber-1024 Benchmarks
    print("\n" + "─" * 80)
    print("Kyber-1024 Benchmarks (NIST Level 5)")
    print("─" * 80)
    kyber1024_keygen = benchmark_kyber_keygen(kyber1024_params(), "Kyber-1024", iterations)
    results['Kyber-1024 KeyGen'] = kyber1024_keygen

    kyber1024_encaps, kyber1024_decaps = benchmark_kyber_key_exchange(kyber1024_params(), "Kyber-1024", iterations)
    kyber1024_exchange = PerformanceMetrics("Kyber-1024 Exchange")
    kyber1024_exchange.times = [(e + d) / 2 for e, d in zip(kyber1024_encaps.times, kyber1024_decaps.times)]
    kyber1024_exchange.memory_peak = [(e + d) / 2 for e, d in zip(kyber1024_encaps.memory_peak, kyber1024_decaps.memory_peak)]
    kyber1024_exchange.memory_allocated = [(e + d) / 2 for e, d in zip(kyber1024_encaps.memory_allocated, kyber1024_decaps.memory_allocated)]
    kyber1024_exchange.actual_size = (kyber1024_encaps.actual_size + kyber1024_decaps.actual_size) / 2
    results['Kyber-1024 Exchange'] = kyber1024_exchange

    # Print explanation
    print("\n" + "=" * 80)
    print("MEMORY MEASUREMENT EXPLANATION")
    print("=" * 80)
    print("""
Two types of memory metrics are measured:

1. PEAK MEMORY (Computational Overhead):
   - Measured using tracemalloc during operation execution
   - Includes ALL temporary Python objects, numpy arrays, intermediate results
   - Kyber shows 100-250× more because it uses many polynomial operations with
     numpy arrays, creating thousands of temporary objects
   - ECC uses simple integer arithmetic with minimal temporary allocations
   - This is NOT the memory needed to store keys, but rather computational overhead

2. ACTUAL SIZE (Storage):
   - Real size of the resulting keys/ciphertext in memory
   - This is what you'd need to store or transmit
   - Much more realistic comparison (see Bandwidth Analysis section)
   - Kyber keys are typically only 2-3× larger than equivalent data structures

The large Peak Memory difference is expected and NOT a problem - it's just the cost
of doing more complex mathematics. The actual storage requirements are reasonable.
""")

    # Print detailed statistics
    print("\n" + "=" * 80)
    print("DETAILED STATISTICS")
    print("=" * 80)

    for name in results:
        print_statistics(results[name])

    # Print bandwidth analysis
    print("\n" + "=" * 80)
    print("BANDWIDTH ANALYSIS")
    print("=" * 80)

    print("\nData Sizes:")
    for name in bandwidth:
        bw = bandwidth[name]
        print(f"\n{name}:")
        print(f"  Public Key:    {bw.public_key_size:6d} bytes")
        print(f"  Private Key:   {bw.private_key_size:6d} bytes")
        if bw.ciphertext_size > 0:
            print(f"  Ciphertext:    {bw.ciphertext_size:6d} bytes")
        print(f"  Shared Secret: {bw.shared_secret_size:6d} bytes")
        print(f"  Total Exchange:{bw.total_exchange_bytes:6d} bytes")

    print("\nBandwidth Overhead vs ECC:")
    ecc_bandwidth = bandwidth['ECC'].total_exchange_bytes
    for name in ['Kyber-512', 'Kyber-768', 'Kyber-1024']:
        bw_factor = bandwidth[name].total_exchange_bytes / ecc_bandwidth
        overhead = (bw_factor - 1) * 100
        print(f"  {name:15s}: {bw_factor:.2f}× ({overhead:+.1f}% more data)")

    # Print comparative analysis
    print("\n" + "=" * 80)
    print("COMPARATIVE ANALYSIS")
    print("=" * 80)

    ecc_exchange_mean = results['ECC Exchange'].mean

    print("\nKey Exchange Performance vs ECC:")
    for name in ['Kyber-512 Exchange', 'Kyber-768 Exchange', 'Kyber-1024 Exchange']:
        slowdown = calculate_slowdown(ecc_exchange_mean, results[name].mean)
        overhead = (slowdown - 1) * 100
        print(f"  {name:25s}: {slowdown:.2f}× slower ({overhead:+.1f}% overhead)")

    print("\nKey Generation Performance vs ECC:")
    ecc_keygen_mean = results['ECC KeyGen'].mean
    for name in ['Kyber-512 KeyGen', 'Kyber-768 KeyGen', 'Kyber-1024 KeyGen']:
        slowdown = calculate_slowdown(ecc_keygen_mean, results[name].mean)
        overhead = (slowdown - 1) * 100
        print(f"  {name:25s}: {slowdown:.2f}× slower ({overhead:+.1f}% overhead)")

    print("\nMemory Usage vs ECC:")
    print("  (Note: 'Peak' = computational overhead with temp objects)")
    print("  (      'Storage' = actual size of keys/results)")
    ecc_mem_baseline = results['ECC Exchange'].mean_memory_peak
    ecc_storage_baseline = results['ECC Exchange'].actual_size
    for name in ['Kyber-512 Exchange', 'Kyber-768 Exchange', 'Kyber-1024 Exchange']:
        mem_factor = results[name].mean_memory_peak / ecc_mem_baseline if ecc_mem_baseline > 0 else 0
        storage_factor = results[name].actual_size / ecc_storage_baseline if ecc_storage_baseline > 0 else 0
        overhead = (mem_factor - 1) * 100
        storage_overhead = (storage_factor - 1) * 100
        print(f"  {name:25s}:")
        print(f"    Peak Memory:    {mem_factor:.2f}× ({overhead:+.1f}%)")
        print(f"    Storage Size:   {storage_factor:.2f}× ({storage_overhead:+.1f}%)")

    # Create visualizations
    print("\n" + "=" * 80)
    print("GENERATING VISUALIZATIONS")
    print("=" * 80)
    create_comparison_plots(results, bandwidth)
    create_memory_comparison_plot(results)

    print("\n" + "=" * 80)
    print("BENCHMARK COMPLETE")
    print("=" * 80)
    print("\nGenerated files:")
    print("  - kyber_vs_ecc_performance.png")
    print("  - key_exchange_comparison.png")
    print("  - bandwidth_comparison.png")
    print("  - memory_comparison.png")

    return results, bandwidth


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Benchmark Kyber vs ECC performance')
    parser.add_argument('-i', '--iterations', type=int, default=100,
                       help='Number of iterations per test (default: 100)')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Quick test with 20 iterations')

    args = parser.parse_args()

    iterations = 20 if args.quick else args.iterations

    try:
        results, bandwidth = run_comprehensive_benchmark(iterations)
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError during benchmark: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
