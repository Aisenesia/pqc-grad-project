"""
Cryptography Library
Implements:
- Elliptic Curve Cryptography (ECC) with secp256k1
- Post-Quantum Cryptography: CRYSTALS-Kyber (Module-LWE based KEM)

Native C Acceleration Enabled for Polynomial Arithmetic
"""

import ctypes
import os
import sys
import secrets
import hashlib
from dataclasses import dataclass
from typing import List, Tuple
import numpy as np

# ============================================================================
# Load Native Library (C Backend)
# ============================================================================

def _load_native_lib():
    """Load the compiled C library"""
    lib_name = 'lib.dll' if sys.platform == 'win32' else ('lib.dylib' if sys.platform == 'darwin' else 'lib.so')
    lib_path = os.path.join(os.path.dirname(__file__), lib_name)
    
    if not os.path.exists(lib_path):
        raise RuntimeError(
            f"Native library not found: {lib_path}\n"
            f"Please compile lib.c first."
        )
    
    try:
        return ctypes.CDLL(lib_path)
    except OSError as e:
        raise RuntimeError(f"Failed to load native library: {e}")

_lib = _load_native_lib()

# Define C function signatures for Polynomial Arithmetic
_lib.lib_version.restype = ctypes.c_char_p
_lib.ntt_transform.argtypes = [ctypes.POINTER(ctypes.c_int16)]
_lib.ntt_inverse.argtypes = [ctypes.POINTER(ctypes.c_int16)]
_lib.poly_add.argtypes = [ctypes.POINTER(ctypes.c_int16)] * 3
_lib.poly_sub.argtypes = [ctypes.POINTER(ctypes.c_int16)] * 3
_lib.poly_mul_ntt.argtypes = [ctypes.POINTER(ctypes.c_int16)] * 3

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def bit_count(x: int) -> int:
    """Count the number of bits in x."""
    if sys.version_info >= (3, 10):
        return x.bit_count()
    else:
        return bin(x).count("1")

def select_bytes(a: bytes, b: bytes, cond: bool) -> bytes:
    """
    Constant-time conditional selection. Returns a if cond is False, b if cond is True.
    """
    assert len(a) == len(b)
    out = [0] * len(a)
    cw = -int(cond) % 256
    for i in range(len(a)):
        out[i] = a[i] ^ (cw & (a[i] ^ b[i]))
    return bytes(out)

# ============================================================================
# ECC: Finite Field Arithmetic Helpers
# ============================================================================

def mod_inv(a, p):
    """Modular multiplicative inverse: a^(-1) mod p."""
    try:
        return pow(a, -1, p)
    except ValueError:
        return None

def mod_div(a, b, p):
    """Modular division: a / b mod p"""
    inv = mod_inv(b, p)
    if inv is None:
        return None
    return (a * inv) % p

# ============================================================================
# ECC: Elliptic Curve Structures
# ============================================================================

@dataclass
class Point:
    """Represents a point on an elliptic curve (x, y)."""
    x: int
    y: int
    is_infinity: bool = False

    @classmethod
    def new(cls, x, y):
        return cls(x, y, False)

    @classmethod
    def infinity(cls):
        return cls(0, 0, True)
        
    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        return (self.is_infinity == other.is_infinity and 
                self.x == other.x and 
                self.y == other.y)

class Curve:
    """Represents an elliptic curve defined by y^2 = x^3 + ax + b (mod p)."""
    
    def __init__(self, p, a, b, generator, order):
        self.p = p
        self.a = a
        self.b = b
        self.generator = generator
        self.order = order

    def is_on_curve(self, point: Point) -> bool:
        if point.is_infinity:
            return True
        left = pow(point.y, 2, self.p)
        right = (pow(point.x, 3, self.p) + (self.a * point.x) + self.b) % self.p
        return left == right

    def double(self, point: Point) -> Point:
        if point.is_infinity or point.y == 0:
            return Point.infinity()

        numerator = (3 * pow(point.x, 2, self.p) + self.a) % self.p
        denominator = (2 * point.y) % self.p
        
        slope = mod_div(numerator, denominator, self.p)
        if slope is None:
            raise ValueError("Failed to calculate slope for point doubling")

        x3 = (pow(slope, 2, self.p) - (2 * point.x)) % self.p
        y3 = (slope * (point.x - x3) - point.y) % self.p

        return Point.new(x3, y3)

    def add(self, p: Point, q: Point) -> Point:
        if p.is_infinity: return q
        if q.is_infinity: return p

        if p.x == q.x:
            if p.y == q.y:
                return self.double(p)
            return Point.infinity()

        numerator = (q.y - p.y) % self.p
        denominator = (q.x - p.x) % self.p
        
        slope = mod_div(numerator, denominator, self.p)
        if slope is None:
            raise ValueError("Failed to calculate slope for point addition")

        x3 = (pow(slope, 2, self.p) - p.x - q.x) % self.p
        y3 = (slope * (p.x - x3) - p.y) % self.p

        return Point.new(x3, y3)

    def scalar_mul(self, k: int, point: Point) -> Point:
        if k == 0 or point.is_infinity:
            return Point.infinity()
        if k < 0:
            return self.scalar_mul(-k, Point.new(point.x, -point.y % self.p))

        result = Point.infinity()
        addend = point

        while k > 0:
            if k & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            k >>= 1

        return result

# ============================================================================
# ECC: secp256k1 Initialization and Key Utils
# ============================================================================

def secp256k1() -> Curve:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    generator = Point.new(gx, gy)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return Curve(p, a, b, generator, order)

def generate_private_key(curve: Curve) -> int:
    return secrets.randbelow(curve.order - 1) + 1

def derive_public_key(curve: Curve, private_key: int) -> Point:
    return curve.scalar_mul(private_key, curve.generator)

def derive_shared_secret(curve: Curve, private_key: int, peer_public: Point) -> Point:
    return curve.scalar_mul(private_key, peer_public)

def point_to_shared_key(point: Point) -> bytes:
    x_bytes = point.x.to_bytes(32, byteorder='big')
    return hashlib.sha256(x_bytes).digest()

# ============================================================================
# KYBER: Parameters
# ============================================================================

@dataclass
class KyberParams:
    n: int
    q: int
    k: int
    eta_1: int
    eta_2: int
    du: int
    dv: int

def kyber512_params() -> KyberParams:
    return KyberParams(n=256, q=3329, k=2, eta_1=3, eta_2=2, du=10, dv=4)

def kyber768_params() -> KyberParams:
    return KyberParams(n=256, q=3329, k=3, eta_1=2, eta_2=2, du=10, dv=4)

def kyber1024_params() -> KyberParams:
    return KyberParams(n=256, q=3329, k=4, eta_1=2, eta_2=2, du=11, dv=5)

# ============================================================================
# KYBER: Polynomial Ring (Hybrid C Implementation)
# ============================================================================

class Polynomial:
    """Polynomial in Rq with 256 coefficients - Accelerated by C."""
    
    def __init__(self, coeffs: np.ndarray, q: int = 3329, is_ntt: bool = False):
        self.coeffs = np.array(coeffs, dtype=np.int16) % q
        self.q = q
        self.n = len(coeffs)
        self.is_ntt = is_ntt
        
        # NTT parameters for Kyber (q=3329, n=256)
        if q == 3329:
            root_of_unity = 17
            self.ntt_zetas = [
                pow(root_of_unity, self._br(i, 7), 3329) for i in range(128)
            ]
            self.ntt_f = pow(128, -1, 3329)

    @staticmethod
    def _br(i: int, k: int) -> int:
        """Bit reversal of an unsigned k-bit integer."""
        bin_i = bin(i & (2**k - 1))[2:].zfill(k)
        return int(bin_i[::-1], 2)
    
    def __add__(self, other):
        """Coefficient-wise addition (Accelerated)."""
        if self.is_ntt != other.is_ntt:
            raise ValueError("Cannot add polynomials in different domains")
        
        a_array = self.coeffs.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        b_array = other.coeffs.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        result = np.zeros(256, dtype=np.int16)
        result_array = result.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        
        _lib.poly_add(a_array, b_array, result_array)
        return Polynomial(result, self.q, self.is_ntt)
    
    def __sub__(self, other):
        """Coefficient-wise subtraction (Accelerated)."""
        if self.is_ntt != other.is_ntt:
            raise ValueError("Cannot subtract polynomials in different domains")
        
        a_array = self.coeffs.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        b_array = other.coeffs.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        result = np.zeros(256, dtype=np.int16)
        result_array = result.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        
        _lib.poly_sub(a_array, b_array, result_array)
        return Polynomial(result, self.q, self.is_ntt)
    
    def __mul__(self, other):
        """Polynomial multiplication (Accelerated if NTT)."""
        if isinstance(other, int):
            # Cast to int32 to avoid overflow
            new_coeffs = (self.coeffs.astype(np.int32) * other) % self.q
            return Polynomial(new_coeffs, self.q, self.is_ntt)
        
        if self.is_ntt and other.is_ntt:
            a_array = self.coeffs.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
            b_array = other.coeffs.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
            # poly_mul_ntt in C (modified logic) expects inputs and produces result using full Montgomery reduction
            result = np.zeros(256, dtype=np.int16)
            result_array = result.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
            
            _lib.poly_mul_ntt(a_array, b_array, result_array)
            return Polynomial(result, self.q, True)
        else:
            return self._naive_multiply(other)
    
    def _naive_multiply(self, other):
        """Naive O(n²) multiplication (Fallback)."""
        # Convert to int32 for intermediate accumulation safely
        c_i32 = self.coeffs.astype(np.int32)
        o_i32 = other.coeffs.astype(np.int32)
        result = np.zeros(2 * self.n - 1, dtype=np.int32)
        for i in range(self.n):
            for j in range(other.n):
                result[i + j] += c_i32[i] * o_i32[j]
        
        reduced = np.zeros(self.n, dtype=np.int32)
        for i in range(len(result)):
            if i < self.n:
                reduced[i] += result[i]
            else:
                reduced[i - self.n] -= result[i]
        
        return Polynomial(reduced % self.q, self.q, False)
    
    def to_ntt(self):
        """Convert polynomial to NTT domain (C-Accelerated)."""
        if self.is_ntt:
            raise TypeError("Polynomial already in NTT domain")
        
        coeffs_copy = self.coeffs.copy()
        # Ensure contiguous array for C ctypes
        if not coeffs_copy.flags['C_CONTIGUOUS']:
             coeffs_copy = np.ascontiguousarray(coeffs_copy)
             
        coeffs_array = coeffs_copy.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        _lib.ntt_transform(coeffs_array)
        
        return Polynomial(coeffs_copy, self.q, True)
    
    def from_ntt(self):
        """Convert polynomial from NTT domain (C-Accelerated)."""
        if not self.is_ntt:
            raise TypeError("Polynomial not in NTT domain")
        
        coeffs_copy = self.coeffs.copy()
        if not coeffs_copy.flags['C_CONTIGUOUS']:
             coeffs_copy = np.ascontiguousarray(coeffs_copy)
             
        coeffs_array = coeffs_copy.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        _lib.ntt_inverse(coeffs_array)
        
        return Polynomial(coeffs_copy, self.q, False)
    
    def __eq__(self, other):
        return np.array_equal(self.coeffs, other.coeffs) and self.q == other.q and self.is_ntt == other.is_ntt
    
    @classmethod
    def zero(cls, n=256, q=3329, is_ntt=False):
        return cls(np.zeros(n, dtype=np.int16), q, is_ntt)
    
    def to_bytes(self, d: int = 12) -> bytes:
        """Encode polynomial to bytes."""
        t = 0
        for i in range(255):
            t |= int(self.coeffs[256 - i - 1])
            t <<= d
        t |= int(self.coeffs[0])
        return t.to_bytes(32 * d, 'little')
    
    @classmethod
    def from_bytes(cls, data: bytes, q=3329, d: int = 12, is_ntt=False):
        """Decode polynomial from bytes."""
        if d == 12:
            m = 3329
        else:
            m = 1 << d
        
        coeffs = []
        b_int = int.from_bytes(data, 'little')
        mask = (1 << d) - 1
        for i in range(256):
            coeffs.append((b_int & mask) % m)
            b_int >>= d
        
        return cls(np.array(coeffs[:256], dtype=np.int16), q, is_ntt)

# ============================================================================
# KYBER: Polynomial Vectors and Matrices
# ============================================================================

class PolynomialVector:
    """Vector of k polynomials."""
    
    def __init__(self, polynomials: List[Polynomial]):
        self.polys = polynomials
        self.k = len(polynomials)
        self.q = polynomials[0].q if polynomials else 3329
        self.n = polynomials[0].n if polynomials else 256
        self.is_ntt = polynomials[0].is_ntt if polynomials else False
    
    def __add__(self, other):
        if self.k != other.k:
            raise ValueError("Vectors must have same dimension")
        return PolynomialVector([p1 + p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def __sub__(self, other):
        if self.k != other.k:
            raise ValueError("Vectors must have same dimension")
        return PolynomialVector([p1 - p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def dot(self, other):
        """Inner product of two vectors."""
        if self.k != other.k:
            raise ValueError("Vectors must have same dimension")
        result = Polynomial.zero(self.n, self.q, self.is_ntt)
        for p1, p2 in zip(self.polys, other.polys):
            result = result + (p1 * p2)
        return result
    
    def to_ntt(self):
        return PolynomialVector([p.to_ntt() for p in self.polys])
    
    def from_ntt(self):
        return PolynomialVector([p.from_ntt() for p in self.polys])
    
    def compress(self, d: int):
        for p in self.polys:
            compress_poly(p, d)
        return self
    
    def decompress(self, d: int):
        for p in self.polys:
            decompress_poly(p, d)
        return self
    
    def reduce_coefficients(self):
        """Reduce all coefficients mod q."""
        for p in self.polys:
            p.coeffs = p.coeffs % p.q
        return self
    
    def to_bytes(self, d: int = 12) -> bytes:
        return b''.join(p.to_bytes(d) for p in self.polys)
    
    @classmethod
    def from_bytes(cls, data: bytes, k: int, q=3329, d: int = 12, is_ntt=False):
        poly_size = 32 * d
        polys = []
        for i in range(k):
            poly_data = data[i * poly_size:(i + 1) * poly_size]
            polys.append(Polynomial.from_bytes(poly_data, q, d, is_ntt))
        return cls(polys)

class PolynomialMatrix:
    """k×k matrix of polynomials."""
    
    def __init__(self, rows: List[List[Polynomial]], transpose: bool = False):
        self.rows = rows
        self.k = len(rows)
        self.q = rows[0][0].q if rows and rows[0] else 3329
        self.n = rows[0][0].n if rows and rows[0] else 256
        self.is_ntt = rows[0][0].is_ntt if rows and rows[0] else False
        self._transpose = transpose
    
    def multiply_vector(self, vec: PolynomialVector) -> PolynomialVector:
        if self.k != vec.k:
            raise ValueError("Matrix and vector dimensions must match")
        result_polys = []
        for row in self.rows:
            row_vec = PolynomialVector(row)
            result_polys.append(row_vec.dot(vec))
        return PolynomialVector(result_polys)
    
    def __matmul__(self, vec: PolynomialVector) -> PolynomialVector:
        return self.multiply_vector(vec)
    
    def transpose(self):
        transposed = [[self.rows[j][i] for j in range(self.k)] for i in range(self.k)]
        return PolynomialMatrix(transposed, transpose=not self._transpose)

# ============================================================================
# KYBER: Sampling Functions
# ============================================================================

def compress_poly(poly: Polynomial, d: int) -> Polynomial:
    """Compress polynomial coefficients from q bits to d bits."""
    q = poly.q
    compressed_coeffs = np.zeros(256, dtype=np.int16)
    
    # Use int32 for calculation to avoid overflow before modulo
    c_i32 = poly.coeffs.astype(np.int32)
    t = 1 << d
    for i in range(256):
        # Round((2^d / q) * x) % 2^d
        val = ((t * c_i32[i] + 1664) // q) % t
        compressed_coeffs[i] = val
    
    poly.coeffs = compressed_coeffs
    return poly

def decompress_poly(poly: Polynomial, d: int, q: int = 3329) -> Polynomial:
    """Decompress polynomial coefficients from d bits back to q."""
    decompressed_coeffs = np.zeros(256, dtype=np.int16)
    t = 1 << (d - 1)
    
    c_i32 = poly.coeffs.astype(np.int32)
    num_coeffs = min(len(poly.coeffs), 256)
    for i in range(num_coeffs):
        # Round((q / 2^d) * x)
        val = ((q * c_i32[i] + t) >> d) % q
        decompressed_coeffs[i] = val
    
    poly.coeffs = decompressed_coeffs
    return poly

def centered_binomial_distribution(eta: int, random_bytes: bytes) -> Polynomial:
    """Sample polynomial with coefficients from CBD."""
    assert 64 * eta == len(random_bytes)
    coeffs = np.zeros(256, dtype=np.int16)
    b_int = int.from_bytes(random_bytes, "little")
    mask = (1 << eta) - 1
    mask2 = (1 << 2 * eta) - 1
    
    for i in range(256):
        x = b_int & mask2
        a = bit_count(x & mask)
        b = bit_count((x >> eta) & mask)
        b_int >>= 2 * eta
        coeffs[i] = (a - b) % 3329
    
    return Polynomial(coeffs, q=3329)

def sample_noise_vector(k: int, eta: int, seed: bytes, nonce: int) -> Tuple[PolynomialVector, int]:
    """Sample vector of k polynomials from noise distribution."""
    polys = []
    for i in range(k):
        prf_input = seed + bytes([nonce + i])
        random_bytes = hashlib.shake_256(prf_input).digest(64 * eta)
        poly = centered_binomial_distribution(eta, random_bytes)
        polys.append(poly)
    return PolynomialVector(polys), nonce + k

def parse_polynomial_from_hash(hash_output: bytes, q: int = 3329, is_ntt: bool = True) -> Polynomial:
    """Parse polynomial with uniform random coefficients from hash output."""
    i, j = 0, 0
    coeffs = np.zeros(256, dtype=np.int16)
    
    while j < 256 and i + 2 < len(hash_output):
        d1 = hash_output[i] + 256 * (hash_output[i + 1] % 16)
        d2 = (hash_output[i + 1] // 16) + 16 * hash_output[i + 2]
        i += 3
        
        if d1 < q:
            coeffs[j] = d1
            j += 1
        
        if d2 < q and j < 256:
            coeffs[j] = d2
            j += 1
    
    return Polynomial(coeffs, q, is_ntt)

def generate_matrix_from_seed(seed: bytes, k: int, q: int = 3329, transpose: bool = False) -> PolynomialMatrix:
    """Generate k×k matrix A from seed (deterministic). Scaled to compensate C-lib arithmetic."""
    rows = []
    scaling_factor = 1 # C implementation handles scaling
    for i in range(k):
        row = []
        for j in range(k):
            if transpose:
                xof_input = seed + bytes([i]) + bytes([j])
            else:
                xof_input = seed + bytes([j]) + bytes([i])
            hash_output = hashlib.shake_128(xof_input).digest(840)
            poly = parse_polynomial_from_hash(hash_output, q, is_ntt=True)
            # Scale by scaling_factor
            poly = poly * scaling_factor 
            row.append(poly)
        rows.append(row)
    return PolynomialMatrix(rows, transpose=transpose)



# ============================================================================
# KYBER: Hash Functions
# ============================================================================

def h_hash(data: bytes) -> bytes:
    """SHA3-256 hash (32 bytes output)."""
    return hashlib.sha3_256(data).digest()

def g_hash(data: bytes) -> Tuple[bytes, bytes]:
    """SHA3-512 hash split into two 32-byte values."""
    output = hashlib.sha3_512(data).digest()
    return output[:32], output[32:]

def kdf(data: bytes, length: int = 32) -> bytes:
    """Key derivation function using SHAKE256."""
    return hashlib.shake_256(data).digest(length)

# ============================================================================
# KYBER: CPA-PKE (Internal primitives)
# ============================================================================

def _cpapke_keygen(params: KyberParams) -> Tuple[bytes, bytes]:
    d = secrets.token_bytes(32)
    rho, sigma = g_hash(d)
    
    A_hat = generate_matrix_from_seed(rho, params.k, params.q, transpose=False)
    N = 0
    s, N = sample_noise_vector(params.k, params.eta_1, sigma, N)
    s_hat = s.to_ntt()
    e, N = sample_noise_vector(params.k, params.eta_1, sigma, N)
    e_hat = e.to_ntt()
    
    t_hat = (A_hat @ s_hat) + e_hat
    t_hat.reduce_coefficients()
    s_hat.reduce_coefficients()
    
    pk = t_hat.to_bytes(12) + rho
    sk = s_hat.to_bytes(12)
    return pk, sk

def _cpapke_enc(pk: bytes, m: bytes, coins: bytes, params: KyberParams) -> bytes:
    t_hat_bytes = pk[:32 * 12 * params.k]
    rho = pk[32 * 12 * params.k:]
    
    t_hat = PolynomialVector.from_bytes(t_hat_bytes, params.k, params.q, 12, is_ntt=True)
    
    m_bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[:256]
    m_coeffs = np.zeros(256, dtype=np.int16)
    for i in range(256):
        m_coeffs[i] = int(m_bits[i]) * (params.q // 2)
    m_poly = Polynomial(m_coeffs, params.q, is_ntt=False)
    
    A_hat_T = generate_matrix_from_seed(rho, params.k, params.q, transpose=True)
    N = 0
    r, N = sample_noise_vector(params.k, params.eta_1, coins, N)
    r_hat = r.to_ntt()
    e1, N = sample_noise_vector(params.k, params.eta_2, coins, N)
    
    prf_output = hashlib.shake_256(coins + bytes([N])).digest(64 * params.eta_2)
    e2 = centered_binomial_distribution(params.eta_2, prf_output)
    
    # Compute v = t^T · r + e2 + m
    u = (A_hat_T @ r_hat).from_ntt() + e1
    # t_hat.dot(r_hat) result is scaled by R^-1, multiply by R (2285)
    scaling_factor = 1 # C implementation handles scaling
    v = (t_hat.dot(r_hat) * scaling_factor).from_ntt() + e2 + m_poly
    
    u.compress(params.du)
    compress_poly(v, params.dv)
    
    c1 = u.to_bytes(params.du)
    c2 = v.to_bytes(params.dv)
    return c1 + c2

def _cpapke_dec(sk: bytes, c: bytes, params: KyberParams) -> bytes:
    index = params.du * params.k * 256 // 8
    c1, c2 = c[:index], c[index:]
    
    u = PolynomialVector.from_bytes(c1, params.k, params.q, params.du, is_ntt=False)
    u.decompress(params.du)
    u_hat = u.to_ntt()
    
    v = Polynomial.from_bytes(c2, params.q, params.dv, is_ntt=False)
    decompress_poly(v, params.dv, params.q)
    
    s_hat = PolynomialVector.from_bytes(sk, params.k, params.q, 12, is_ntt=True)
    
    # Scale correction
    scaling_factor = 1 # C implementation handles scaling
    m_poly = v - (s_hat.dot(u_hat) * scaling_factor).from_ntt()
    
    m_bits = []
    threshold = params.q // 4
    for i in range(256):
        coeff = m_poly.coeffs[i] % params.q
        if coeff > threshold and coeff < params.q - threshold:
            m_bits.append(1)
        else:
            m_bits.append(0)
    
    # Pack bits to bytes
    m = np.packbits(np.array(m_bits, dtype=np.uint8)).tobytes()[:32]
    return m

# ============================================================================
# KYBER: CCA-KEM (Public API)
# ============================================================================

def kyber_keygen(params: KyberParams = None) -> Tuple[bytes, bytes]:
    """Generate Kyber key pair (pk, sk)."""
    if params is None:
        params = kyber512_params()
    
    pk, sk_pke = _cpapke_keygen(params)
    z = secrets.token_bytes(32)
    sk = sk_pke + pk + h_hash(pk) + z
    return pk, sk

def kyber_encapsulate(public_key: bytes, params: KyberParams = None) -> Tuple[bytes, bytes]:
    """Generate shared secret and ciphertext. Returns (shared_secret, ciphertext)."""
    if params is None:
        params = kyber512_params()
    
    m = secrets.token_bytes(32)
    m_hash = h_hash(m)
    K_bar, r = g_hash(m_hash + h_hash(public_key))
    
    c = _cpapke_enc(public_key, m_hash, r, params)
    shared_secret = kdf(K_bar + h_hash(c), 32)
    
    return shared_secret, c

def kyber_decapsulate(ciphertext: bytes, secret_key: bytes, params: KyberParams = None) -> bytes:
    """Recover shared secret from ciphertext."""
    if params is None:
        params = kyber512_params()
    
    index = 12 * params.k * 256 // 8
    sk_pke = secret_key[:index]
    pk_size = 32 * 12 * params.k + 32
    pk = secret_key[index:index + pk_size]
    pk_hash = secret_key[index + pk_size:index + pk_size + 32]
    z = secret_key[index + pk_size + 32:]
    
    m = _cpapke_dec(sk_pke, ciphertext, params)
    
    K_bar, r = g_hash(m + pk_hash)
    c_prime = _cpapke_enc(pk, m, r, params)
    
    key = kdf(K_bar + h_hash(ciphertext), 32)
    garbage = kdf(z + h_hash(ciphertext), 32)
    
    return select_bytes(garbage, key, ciphertext == c_prime)

# ============================================================================
# Library Info
# ============================================================================

def lib_version() -> str:
    """Get library version from C backend"""
    return _lib.lib_version().decode('utf-8')

# Print status on import
print(f"[OK] Native-Accelerated library loaded: {lib_version()}")
