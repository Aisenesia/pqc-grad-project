"""
Cryptography Library
Implements:
- Elliptic Curve Cryptography (ECC) with secp256k1
- Post-Quantum Cryptography: CRYSTALS-Kyber (Module-LWE based KEM)
"""

import secrets
import hashlib
from dataclasses import dataclass
from typing import List
import numpy as np
import sys


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
    Constant-time conditional selection between bytes a or b.
    Returns a if cond is False, b if cond is True.
    Critical for security in FO transform.
    """
    assert len(a) == len(b)
    out = [0] * len(a)
    cw = -cond % 256
    for i in range(len(a)):
        out[i] = a[i] ^ (cw & (a[i] ^ b[i]))
    return bytes(out)


# ============================================================================
# ECC: Finite Field Arithmetic Helpers
# ============================================================================
# These functions provide the fundamental mathematical operations over finite fields
# required for Elliptic Curve Cryptography. Since ECC works over integers modulo p,
# we need specialized division (via modular inverse) rather than standard floating-point division.

def mod_inv(a, p):
    """
    Modular multiplicative inverse: a^(-1) mod p.
    Python's pow(a, -1, p) uses the Extended Euclidean Algorithm internally.
    """
    try:
        return pow(a, -1, p)
    except ValueError:
        return None  # No inverse exists (gcd(a, p) != 1)

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
    """
    Represents a point on an elliptic curve (x, y).
    Points are the public keys and intermediate values in ECC.
    The 'point at infinity' acts as the identity element (zero) for the group.
    """
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
    """
    Represents an elliptic curve defined by the equation y^2 = x^3 + ax + b (mod p).
    This class encapsulates the curve parameters and the group laws (addition, doubling)
    that define how points interact.
    """
    
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
        right = (pow(point.x, 3, self.p) + (self.a * point.x) + self.b) % self.p # y^2 ?= x^3 + ax + b mod p
        return left == right

    def double(self, point: Point) -> Point:
        """
        Point doubling: compute 2P.
        This is a special case of addition where P + P is computed using the tangent line slope.
        """
        if point.is_infinity or point.y == 0:
            return Point.infinity()

        # Slope lambda = (3x^2 + a) / (2y) mod p
        numerator = (3 * pow(point.x, 2, self.p) + self.a) % self.p # 3x1^2 + a
        denominator = (2 * point.y) % self.p
        
        slope = mod_div(numerator, denominator, self.p)
        if slope is None:
            raise ValueError("Failed to calculate slope for point doubling")

        # x3 = lambda^2 - 2x mod p
        x3 = (pow(slope, 2, self.p) - (2 * point.x)) % self.p
        
        # y3 = lambda(x - x3) - y mod p
        y3 = (slope * (point.x - x3) - point.y) % self.p

        return Point.new(x3, y3)

    def add(self, p: Point, q: Point) -> Point:
        """
        Point addition: compute P + Q.
        Geometrically, this involves drawing a line through P and Q and finding the third intersection point.
        """
        if p.is_infinity: return q
        if q.is_infinity: return p

        if p.x == q.x:
            if p.y == q.y:
                return self.double(p)
            # Inverse points (vertical line) -> Infinity
            return Point.infinity()

        # Slope lambda = (y2 - y1) / (x2 - x1) mod p
        numerator = (q.y - p.y) % self.p
        denominator = (q.x - p.x) % self.p
        
        slope = mod_div(numerator, denominator, self.p)
        if slope is None:
            raise ValueError("Failed to calculate slope for point addition")

        # x3 = lambda^2 - x1 - x2 mod p
        x3 = (pow(slope, 2, self.p) - p.x - q.x) % self.p
        
        # y3 = lambda(x1 - x3) - y1 mod p
        y3 = (slope * (p.x - x3) - p.y) % self.p

        return Point.new(x3, y3)

    def scalar_mul(self, k: int, point: Point) -> Point:
        """
        Double-and-add algorithm for k * P.
        This is the core operation for generating public keys and shared secrets.
        It efficiently computes the scalar multiplication in O(log k) steps.
        """
        if k == 0 or point.is_infinity:
            return Point.infinity()

        # Handle negative scalars
        if k < 0:
            return self.scalar_mul(-k, Point.new(point.x, -point.y % self.p))
            # % is used to ensure y is within field range

        result = Point.infinity() # Point at infinity (identity element)
        addend = point # Initialize addend to P

        while k > 0: # shift through bits of k, since binary it will go log(k) times
            if k & 1:  # Check if LSB is 1
                result = self.add(result, addend)
            addend = self.double(addend)
            k >>= 1  # Shift right to process the next bit

        return result

# ============================================================================
# ECC: secp256k1 Initialization and Key Utils
# ============================================================================

def secp256k1() -> Curve:
    """
    Initialize standard secp256k1 curve parameters.
    This specific curve is widely used in cryptocurrencies like Bitcoin and Ethereum.
    It is defined over a prime field with specific constants a, b, and a generator point G.
    """
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    # 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
    # 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    generator = Point.new(gx, gy)
    # Order of the group generated by G
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    return Curve(p, a, b, generator, order)

def generate_private_key(curve: Curve) -> int:
    """
    Generate a crypto-secure random private key.
    A private key in ECC is simply a random integer k such that 1 <= k < order.
    It represents the scalar multiplier for the generator point.
    """
    # range [1, order - 1]
    return secrets.randbelow(curve.order - 1) + 1

def derive_public_key(curve: Curve, private_key: int) -> Point:
    """
    Derive the public key from a private key.
    The public key is the result of multiplying the generator point G by the private key scalar k.
    Public Key P = k * G. This is a one-way function (Discrete Logarithm Problem).
    """
    return curve.scalar_mul(private_key, curve.generator)

def derive_shared_secret(curve: Curve, private_key: int, peer_public: Point) -> Point:
    """
    Compute the shared secret using Elliptic Curve Diffie-Hellman (ECDH).
    Alice computes: S = a * Q_b
    Bob computes:   S = b * Q_a
    Since Q_b = b * G and Q_a = a * G, both compute S = (ab) * G.
    """
    return curve.scalar_mul(private_key, peer_public)

def point_to_shared_key(point: Point) -> bytes:
    """
    Derive a symmetric key from the shared point.
    Usually, the x-coordinate of the shared point is hashed to produce a fixed-length key
    suitable for symmetric encryption (e.g., AES).
    """
    # 256 bits = 32 bytes
    x_bytes = point.x.to_bytes(32, byteorder='big')
    return hashlib.sha256(x_bytes).digest()

def point_to_shared_key(point: Point) -> bytes:
    """
    Derive a symmetric key from the shared point.
    Usually, the x-coordinate of the shared point is hashed to produce a fixed-length key
    suitable for symmetric encryption (e.g., AES).
    """
    # 256 bits = 32 bytes
    x_bytes = point.x.to_bytes(32, byteorder='big')
    return hashlib.sha256(x_bytes).digest()


# ============================================================================
# KYBER: Parameters
# ============================================================================

@dataclass
class KyberParams:
    n: int      # Polynomial degree (256)
    q: int      # Modulus (3329)
    k: int      # Module rank (2/3/4 for Kyber512/768/1024)
    eta_1: int  # Noise parameter for secret/error
    eta_2: int  # Noise parameter for encryption
    du: int     # Compression parameter for u
    dv: int     # Compression parameter for v


def kyber512_params() -> KyberParams:
    return KyberParams(n=256, q=3329, k=2, eta_1=3, eta_2=2, du=10, dv=4)


def kyber768_params() -> KyberParams:
    return KyberParams(n=256, q=3329, k=3, eta_1=2, eta_2=2, du=10, dv=4)


def kyber1024_params() -> KyberParams:
    return KyberParams(n=256, q=3329, k=4, eta_1=2, eta_2=2, du=11, dv=5)


# ============================================================================
# KYBER: Polynomial Ring (Rq = Zq[X]/(X^256 + 1))
# ============================================================================

class Polynomial:
    """Polynomial in Rq with 256 coefficients."""
    
    def __init__(self, coeffs: np.ndarray, q: int = 3329, is_ntt: bool = False):
        """
        Note: Negative coefficients are stored as positive mod q.
        E.g., -1 → 3328, -2 → 3327, -3 → 3326
        """
        self.coeffs = np.array(coeffs, dtype=np.int32) % q
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
        """Coefficient-wise addition mod q."""
        if self.n != other.n or self.q != other.q:
            raise ValueError("Polynomials must have same degree and modulus")
        if self.is_ntt != other.is_ntt:
            raise ValueError("Cannot add polynomials in different domains")
        return Polynomial((self.coeffs + other.coeffs) % self.q, self.q, self.is_ntt)
    
    def __sub__(self, other):
        """Coefficient-wise subtraction mod q."""
        if self.n != other.n or self.q != other.q:
            raise ValueError("Polynomials must have same degree and modulus")
        if self.is_ntt != other.is_ntt:
            raise ValueError("Cannot subtract polynomials in different domains")
        return Polynomial((self.coeffs - other.coeffs) % self.q, self.q, self.is_ntt)
    
    def __mul__(self, other):
        """
        Polynomial multiplication.
        Uses NTT if both polynomials are in NTT domain, otherwise naive multiplication.
        """
        if isinstance(other, int):
            return Polynomial((self.coeffs * other) % self.q, self.q, self.is_ntt)
        
        if self.is_ntt and other.is_ntt:
            # NTT multiplication - O(n) instead of O(n²)
            return self._ntt_multiply(other)
        else:
            # Naive convolution - O(n²)
            return self._naive_multiply(other)
    
    def _naive_multiply(self, other):
        """Naive O(n²) polynomial multiplication."""
        result = np.zeros(2 * self.n - 1, dtype=np.int32)
        for i in range(self.n):
            for j in range(other.n):
                result[i + j] += self.coeffs[i] * other.coeffs[j]
        
        # Reduce mod (X^n + 1): X^n ≡ -1
        reduced = np.zeros(self.n, dtype=np.int32)
        for i in range(len(result)):
            if i < self.n:
                reduced[i] += result[i]
            else:
                reduced[i - self.n] -= result[i]
        
        return Polynomial(reduced % self.q, self.q, False)
    
    def _ntt_multiply(self, other):
        """NTT domain multiplication - coefficient-wise with base multiplication."""
        new_coeffs = self._ntt_coefficient_multiplication(self.coeffs, other.coeffs)
        return Polynomial(np.array(new_coeffs, dtype=np.int32), self.q, True)
    
    @staticmethod
    def _ntt_base_multiplication(a0, a1, b0, b1, zeta, q=3329):
        """Base case for NTT multiplication. Uses int64 to prevent overflow."""
        # Cast to int64 to prevent overflow
        a0, a1, b0, b1, zeta = np.int64(a0), np.int64(a1), np.int64(b0), np.int64(b1), np.int64(zeta)
        r0 = int((a0 * b0 + zeta * a1 * b1) % q)
        r1 = int((a1 * b0 + a0 * b1) % q)
        return r0, r1
    
    def _ntt_coefficient_multiplication(self, f_coeffs, g_coeffs):
        """Coefficient multiplication in NTT domain."""
        new_coeffs = []
        for i in range(64):
            r0, r1 = self._ntt_base_multiplication(
                f_coeffs[4 * i + 0],
                f_coeffs[4 * i + 1],
                g_coeffs[4 * i + 0],
                g_coeffs[4 * i + 1],
                self.ntt_zetas[64 + i],
                self.q
            )
            r2, r3 = self._ntt_base_multiplication(
                f_coeffs[4 * i + 2],
                f_coeffs[4 * i + 3],
                g_coeffs[4 * i + 2],
                g_coeffs[4 * i + 3],
                -self.ntt_zetas[64 + i],
                self.q
            )
            new_coeffs += [r0, r1, r2, r3]
        return new_coeffs
    
    def to_ntt(self):
        """
        Convert polynomial to NTT domain.
        Input in standard order, output in bit-reversed order.
        """
        if self.is_ntt:
            raise TypeError("Polynomial already in NTT domain")
        
        k, l = 1, 128
        coeffs = self.coeffs.copy()
        
        while l >= 2:
            start = 0
            while start < 256:
                zeta = self.ntt_zetas[k]
                k = k + 1
                for j in range(start, start + l):
                    t = (zeta * coeffs[j + l]) % self.q
                    coeffs[j + l] = (coeffs[j] - t) % self.q
                    coeffs[j] = (coeffs[j] + t) % self.q
                start = l + (j + 1)
            l = l >> 1
        
        return Polynomial(coeffs % self.q, self.q, True)
    
    def from_ntt(self):
        """
        Convert polynomial from NTT domain.
        Input in bit-reversed order, output in standard order.
        """
        if not self.is_ntt:
            raise TypeError("Polynomial not in NTT domain")
        
        l, l_upper = 2, 128
        k = l_upper - 1
        coeffs = self.coeffs.copy()
        
        while l <= 128:
            start = 0
            while start < 256:
                zeta = self.ntt_zetas[k]
                k = k - 1
                for j in range(start, start + l):
                    t = coeffs[j]
                    coeffs[j] = (t + coeffs[j + l]) % self.q
                    coeffs[j + l] = (coeffs[j + l] - t) % self.q
                    coeffs[j + l] = (zeta * coeffs[j + l]) % self.q
                start = j + l + 1
            l = l << 1
        
        # Final scaling
        for j in range(256):
            coeffs[j] = (coeffs[j] * self.ntt_f) % self.q
        
        return Polynomial(coeffs, self.q, False)
    
    def __eq__(self, other):
        return np.array_equal(self.coeffs, other.coeffs) and self.q == other.q and self.is_ntt == other.is_ntt
    
    def __repr__(self):
        ntt_str = " (NTT)" if self.is_ntt else ""
        return f"Poly([{self.coeffs[0]}, {self.coeffs[1]}, ..., {self.coeffs[-1]}] mod {self.q}{ntt_str})"
    
    @classmethod
    def zero(cls, n=256, q=3329, is_ntt=False):
        return cls(np.zeros(n, dtype=np.int32), q, is_ntt)
    
    def to_bytes(self, d: int = 12) -> bytes:
        """Encode polynomial to bytes with d-bit coefficients."""
        t = 0
        for i in range(255):
            t |= int(self.coeffs[256 - i - 1])
            t <<= d
        t |= int(self.coeffs[0])
        return t.to_bytes(32 * d, 'little')
    
    @classmethod
    def from_bytes(cls, data: bytes, q=3329, d: int = 12, is_ntt=False):
        """Decode polynomial from bytes with d-bit coefficients."""
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
        
        return cls(np.array(coeffs[:256], dtype=np.int32), q, is_ntt)


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
        """Convert all polynomials to NTT domain."""
        return PolynomialVector([p.to_ntt() for p in self.polys])
    
    def from_ntt(self):
        """Convert all polynomials from NTT domain."""
        return PolynomialVector([p.from_ntt() for p in self.polys])
    
    def compress(self, d: int):
        """Compress all polynomials."""
        for p in self.polys:
            compress_poly(p, d)
        return self
    
    def decompress(self, d: int):
        """Decompress all polynomials."""
        for p in self.polys:
            decompress_poly(p, d)
        return self
    
    def reduce_coefficients(self):
        """Reduce all coefficients mod q."""
        for p in self.polys:
            p.coeffs = p.coeffs % p.q
        return self
    
    def __repr__(self):
        ntt_str = " (NTT)" if self.is_ntt else ""
        return f"PolyVec(k={self.k}, n={self.n}, q={self.q}{ntt_str})"
    
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
        """Matrix-vector multiplication: A·v"""
        if self.k != vec.k:
            raise ValueError("Matrix and vector dimensions must match")
        result_polys = []
        for row in self.rows:
            row_vec = PolynomialVector(row)
            result_polys.append(row_vec.dot(vec))
        return PolynomialVector(result_polys)
    
    def __matmul__(self, vec: PolynomialVector) -> PolynomialVector:
        """Matrix-vector multiplication using @ operator."""
        return self.multiply_vector(vec)
    
    def transpose(self):
        """Transpose the matrix."""
        transposed = [[self.rows[j][i] for j in range(self.k)] for i in range(self.k)]
        return PolynomialMatrix(transposed, transpose=not self._transpose)
    
    def __repr__(self):
        ntt_str = " (NTT)" if self.is_ntt else ""
        return f"PolyMatrix({self.k}×{self.k}, n={self.n}, q={self.q}{ntt_str})"


# ============================================================================
# KYBER: Sampling Functions
# ============================================================================

def compress_poly(poly: Polynomial, d: int) -> Polynomial:
    """Compress polynomial coefficients from q bits to d bits."""
    q = poly.q
    compressed_coeffs = np.zeros(256, dtype=np.int32)
    
    for i in range(256):
        # Round((2^d / q) * x) % 2^d
        t = 1 << d
        compressed_coeffs[i] = ((t * poly.coeffs[i] + 1664) // q) % t  # 1664 = 3329 // 2
    
    poly.coeffs = compressed_coeffs
    return poly


def decompress_poly(poly: Polynomial, d: int, q: int = 3329) -> Polynomial:
    """Decompress polynomial coefficients from d bits back to q."""
    decompressed_coeffs = np.zeros(256, dtype=np.int32)
    t = 1 << (d - 1)
    
    # Handle case where poly may have fewer coefficients
    num_coeffs = min(len(poly.coeffs), 256)
    for i in range(num_coeffs):
        # Round((q / 2^d) * x)
        decompressed_coeffs[i] = ((q * poly.coeffs[i] + t) >> d) % q
    
    poly.coeffs = decompressed_coeffs
    return poly


def centered_binomial_distribution(eta: int, random_bytes: bytes) -> Polynomial:
    """
    Sample polynomial with coefficients from CBD.
    Generates small coefficients in range [-eta, +eta] centered at 0.
    This "noise" is what makes LWE quantum-resistant.
    
    Uses improved bit-counting method.
    """
    assert 64 * eta == len(random_bytes)
    coeffs = [0 for _ in range(256)]
    b_int = int.from_bytes(random_bytes, "little")
    mask = (1 << eta) - 1
    mask2 = (1 << 2 * eta) - 1
    
    for i in range(256):
        x = b_int & mask2
        a = bit_count(x & mask)
        b = bit_count((x >> eta) & mask)
        b_int >>= 2 * eta
        coeffs[i] = (a - b) % 3329
    
    return Polynomial(np.array(coeffs, dtype=np.int32), q=3329)


def sample_noise_vector(k: int, eta: int, seed: bytes, nonce: int) -> tuple[PolynomialVector, int]:
    """Sample vector of k polynomials from noise distribution. Returns (vector, updated_nonce)."""
    polys = []
    for i in range(k):
        prf_input = seed + bytes([nonce + i])
        random_bytes = hashlib.shake_256(prf_input).digest(64 * eta)
        poly = centered_binomial_distribution(eta, random_bytes)
        polys.append(poly)
    return PolynomialVector(polys), nonce + k


def parse_polynomial_from_hash(hash_output: bytes, q: int = 3329, is_ntt: bool = True) -> Polynomial:
    """
    Parse polynomial with uniform random coefficients from hash output.
    Returns polynomial in NTT domain by default (for matrix A).
    
    Algorithm 1 (Parse) / Algorithm 6 (Sample NTT)
    """
    i, j = 0, 0
    coeffs = [0 for _ in range(256)]
    
    while j < 256:
        d1 = hash_output[i] + 256 * (hash_output[i + 1] % 16)
        d2 = (hash_output[i + 1] // 16) + 16 * hash_output[i + 2]
        i += 3
        
        if d1 < q:
            coeffs[j] = d1
            j += 1
        
        if d2 < q and j < 256:
            coeffs[j] = d2
            j += 1
    
    return Polynomial(np.array(coeffs, dtype=np.int32), q, is_ntt)


def generate_matrix_from_seed(seed: bytes, k: int, q: int = 3329, transpose: bool = False) -> PolynomialMatrix:
    """
    Generate k×k matrix A from seed (deterministic).
    Matrix elements are in NTT domain for efficient multiplication.
    When transpose=True, generates A^T directly.
    """
    rows = []
    for i in range(k):
        row = []
        for j in range(k):
            # XOF with proper byte ordering
            if transpose:
                xof_input = seed + bytes([i]) + bytes([j])
            else:
                xof_input = seed + bytes([j]) + bytes([i])
            hash_output = hashlib.shake_128(xof_input).digest(840)
            poly = parse_polynomial_from_hash(hash_output, q, is_ntt=True)
            row.append(poly)
        rows.append(row)
    return PolynomialMatrix(rows, transpose=transpose)


# ============================================================================
# KYBER: Hash Functions
# ============================================================================

def h_hash(data: bytes) -> bytes:
    """SHA3-256 hash (32 bytes output)."""
    return hashlib.sha3_256(data).digest()

def g_hash(data: bytes) -> tuple[bytes, bytes]:
    """SHA3-512 hash split into two 32-byte values."""
    output = hashlib.sha3_512(data).digest()
    return output[:32], output[32:]

def kdf(data: bytes, length: int = 32) -> bytes:
    """Key derivation function using SHAKE256."""
    return hashlib.shake_256(data).digest(length)


# ============================================================================
# KYBER: CPA-PKE (IND-CPA secure) - Internal primitives
# ============================================================================

def _cpapke_keygen(params: KyberParams) -> tuple[bytes, bytes]:
    """
    CPA-PKE Key Generation (Algorithm 4).
    Generate public key and secret key for the underlying PKE.
    Uses NTT domain for efficiency.
    """
    # Generate random value, hash and split
    d = secrets.token_bytes(32)
    rho, sigma = g_hash(d)
    
    # Generate the matrix A ∈ R^k×k (in NTT domain)
    A_hat = generate_matrix_from_seed(rho, params.k, params.q, transpose=False)
    
    # Set counter for PRF
    N = 0
    
    # Generate the secret vector s ∈ R^k
    s, N = sample_noise_vector(params.k, params.eta_1, sigma, N)
    s_hat = s.to_ntt()
    
    # Generate the error vector e ∈ R^k
    e, N = sample_noise_vector(params.k, params.eta_1, sigma, N)
    e_hat = e.to_ntt()
    
    # Construct the public key: t = A·s + e (in NTT domain)
    t_hat = (A_hat @ s_hat) + e_hat
    
    # Reduce vectors mod q
    t_hat.reduce_coefficients()
    s_hat.reduce_coefficients()
    
    # Encode to bytes
    pk = t_hat.to_bytes(12) + rho
    sk = s_hat.to_bytes(12)
    
    return pk, sk


def _cpapke_enc(pk: bytes, m: bytes, coins: bytes, params: KyberParams) -> bytes:
    """
    CPA-PKE Encryption (Algorithm 5).
    Encrypt a 32-byte message m using public key pk and randomness coins.
    """
    # Unpack public key
    t_hat_bytes = pk[:32 * 12 * params.k]
    rho = pk[32 * 12 * params.k:]
    
    # Decode t_hat vector from public key (in NTT domain)
    t_hat = PolynomialVector.from_bytes(t_hat_bytes, params.k, params.q, 12, is_ntt=True)
    
    # Encode message as polynomial
    m_bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[:256]
    m_coeffs = np.zeros(256, dtype=np.int32)
    for i in range(256):
        m_coeffs[i] = int(m_bits[i]) * (params.q // 2)
    m_poly = Polynomial(m_coeffs, params.q, is_ntt=False)
    
    # Generate the matrix A^T ∈ R^k×k (in NTT domain)
    A_hat_T = generate_matrix_from_seed(rho, params.k, params.q, transpose=True)
    
    # Set counter for PRF
    N = 0
    
    # Generate the error vector r ∈ R^k
    r, N = sample_noise_vector(params.k, params.eta_1, coins, N)
    r_hat = r.to_ntt()
    
    # Generate the error vector e1 ∈ R^k
    e1, N = sample_noise_vector(params.k, params.eta_2, coins, N)
    
    # Generate the error polynomial e2 ∈ R
    prf_output = hashlib.shake_256(coins + bytes([N])).digest(64 * params.eta_2)
    e2 = centered_binomial_distribution(params.eta_2, prf_output)
    
    # Compute u = A^T · r + e1
    u = (A_hat_T @ r_hat).from_ntt() + e1
    
    # Compute v = t^T · r + e2 + m
    v = t_hat.dot(r_hat).from_ntt() + e2 + m_poly
    
    # Compress and encode ciphertext
    u.compress(params.du)
    compress_poly(v, params.dv)
    
    c1 = u.to_bytes(params.du)
    c2 = v.to_bytes(params.dv)
    
    return c1 + c2


def _cpapke_dec(sk: bytes, c: bytes, params: KyberParams) -> bytes:
    """
    CPA-PKE Decryption (Algorithm 6).
    Decrypt ciphertext c using secret key sk.
    """
    # Split ciphertext
    index = params.du * params.k * 256 // 8
    c1, c2 = c[:index], c[index:]
    
    # Decode and decompress u
    u = PolynomialVector.from_bytes(c1, params.k, params.q, params.du, is_ntt=False)
    u.decompress(params.du)
    u_hat = u.to_ntt()
    
    # Decode and decompress v
    v = Polynomial.from_bytes(c2, params.q, params.dv, is_ntt=False)
    decompress_poly(v, params.dv, params.q)
    
    # Decode secret key s_hat (in NTT domain)
    s_hat = PolynomialVector.from_bytes(sk, params.k, params.q, 12, is_ntt=True)
    
    # Recover message: m = v - s^T · u
    m_poly = v - s_hat.dot(u_hat).from_ntt()
    
    # Decode message bits
    m_bits = []
    threshold = params.q // 4
    for i in range(256):
        coeff = m_poly.coeffs[i] % params.q
        # If closer to q/2 than to 0, it's a 1 bit
        if coeff > threshold and coeff < params.q - threshold:
            m_bits.append(1)
        else:
            m_bits.append(0)
    
    # Convert bits to bytes
    m = np.packbits(np.array(m_bits, dtype=np.uint8)).tobytes()[:32]
    
    return m


# ============================================================================
# KYBER: CCA-KEM (IND-CCA secure) - Public API with Fujisaki-Okamoto Transform
# ============================================================================

def kyber_keygen(params: KyberParams = None) -> tuple[bytes, bytes]:
    """
    CCA-KEM Key Generation (Algorithm 7).
    Generate Kyber key pair with FO transform.
    
    Returns:
        (public_key, secret_key)
        secret_key = sk_pke || pk || H(pk) || z
    """
    if params is None:
        params = kyber512_params()
    
    # Generate CPA-PKE keypair
    pk, sk_pke = _cpapke_keygen(params)
    
    # Generate random z for implicit rejection
    z = secrets.token_bytes(32)
    
    # Extended secret key: sk = sk_pke || pk || H(pk) || z
    sk = sk_pke + pk + h_hash(pk) + z
    
    return pk, sk


def kyber_encapsulate(public_key: bytes, params: KyberParams = None) -> tuple[bytes, bytes]:
    """
    CCA-KEM Encapsulation (Algorithm 8) with Fujisaki-Okamoto Transform.
    Generate shared secret and ciphertext.
    
    Args:
        public_key: Bob's public key
        params: Kyber parameters
    
    Returns:
        (shared_secret, ciphertext)
    """
    if params is None:
        params = kyber512_params()
    
    # Generate random message
    m = secrets.token_bytes(32)
    
    # Hash message
    m_hash = h_hash(m)
    
    # Compute K_bar and randomness r
    K_bar, r = g_hash(m_hash + h_hash(public_key))
    
    # Perform CPA-PKE encryption
    c = _cpapke_enc(public_key, m_hash, r, params)
    
    # Derive shared secret from K_bar and ciphertext hash
    shared_secret = kdf(K_bar + h_hash(c), 32)
    
    return shared_secret, c


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes, params: KyberParams = None) -> bytes:
    """
    CCA-KEM Decapsulation (Algorithm 9) with Fujisaki-Okamoto Transform.
    Recover shared secret from ciphertext using secret key.
    
    Includes re-encryption check for CCA security and constant-time
    failure handling (implicit rejection).
    
    Args:
        ciphertext: Alice's ciphertext
        secret_key: Bob's secret key (extended format)
        params: Kyber parameters
    
    Returns:
        shared_secret
    """
    if params is None:
        params = kyber512_params()
    
    # Unpack extended secret key: sk = sk_pke || pk || H(pk) || z
    index = 12 * params.k * 256 // 8
    sk_pke = secret_key[:index]
    
    # Calculate pk size
    pk_size = 32 * 12 * params.k + 32  # t_hat + rho
    pk = secret_key[index:index + pk_size]
    pk_hash = secret_key[index + pk_size:index + pk_size + 32]
    z = secret_key[index + pk_size + 32:]
    
    # Decrypt ciphertext
    m = _cpapke_dec(sk_pke, ciphertext, params)
    
    # Re-encapsulation check (FO Transform)
    K_bar, r = g_hash(m + pk_hash)
    c_prime = _cpapke_enc(pk, m, r, params)
    
    # Derive keys
    key = kdf(K_bar + h_hash(ciphertext), 32)
    garbage = kdf(z + h_hash(ciphertext), 32)
    
    # Constant-time selection: return key if c == c_prime, else garbage
    # This is critical for CCA security!
    return select_bytes(garbage, key, ciphertext == c_prime)


# ============================================================================
# ECC: Tests (Runnable Block)
# ============================================================================

if __name__ == "__main__":
    print("Running ECC Tests...")
    
    # Initialize Curve
    curve = secp256k1()
    
    # 1. Test Generator
    assert curve.is_on_curve(curve.generator), "Generator should be on curve"
    
    # 2. Test Doubling vs Addition
    double_g = curve.double(curve.generator)
    add_g = curve.add(curve.generator, curve.generator)
    assert double_g == add_g, "Doubling should equal adding point to itself"
    assert curve.is_on_curve(double_g), "Doubled point should be on curve"
    
    # 3. Test Scalar Multiplication
    two_g = curve.scalar_mul(2, curve.generator)
    assert two_g == double_g, "Scalar mult by 2 should equal doubling"
    
    # 4. Test Key Exchange Simulation
    alice_priv = generate_private_key(curve)
    bob_priv = generate_private_key(curve)

    print(f"Alice Private Key: {alice_priv}")
    print(f"Bob Private Key: {bob_priv}")
    
    alice_pub = derive_public_key(curve, alice_priv)
    bob_pub = derive_public_key(curve, bob_priv)

    print(f"Alice Public Key: ({alice_pub.x}, {alice_pub.y})")
    print(f"Bob Public Key: ({bob_pub.x}, {bob_pub.y})")
    
    # Alice calculates shared secret using her Priv + Bob's Pub
    shared_alice = derive_shared_secret(curve, alice_priv, bob_pub)
    
    # Bob calculates shared secret using his Priv + Alice's Pub
    shared_bob = derive_shared_secret(curve, bob_priv, alice_pub)

    print(f"Shared Secret (Alice): ({shared_alice.x}, {shared_alice.y})")
    print(f"Shared Secret (Bob): ({shared_bob.x}, {shared_bob.y})")
    
    assert shared_alice == shared_bob, "Shared secrets must match"
    
    # 5. Test Key Derivation
    key_alice = point_to_shared_key(shared_alice)
    key_bob = point_to_shared_key(shared_bob)
    
    print(f"Tests Passed!")
    print(f"Sample Shared Key (Hex): {key_alice.hex()}")


# ============================================================================
# KYBER: Tests (Runnable Block)
# ============================================================================

def test_kyber():
    """Run comprehensive Kyber tests."""
    print("\n" + "="*60)
    print("KYBER POST-QUANTUM CRYPTOGRAPHY TESTS")
    print("="*60 + "\n")
    
    # Polynomial arithmetic
    p1 = Polynomial(np.array([1, 2, 3] + [0] * 253), q=3329, is_ntt=False)
    p2 = Polynomial(np.array([4, 5, 6] + [0] * 253), q=3329, is_ntt=False)
    p_add = p1 + p2
    p_mul = p1 * p2
    print(f"Polynomial addition: {p_add}")
    print(f"Polynomial multiplication (first 5): {p_mul.coeffs[:5]}\n")
    
    # NTT test
    print("NTT Transform Test:")
    test_poly = Polynomial(np.random.randint(0, 100, 256), q=3329, is_ntt=False)
    test_ntt = test_poly.to_ntt()
    test_back = test_ntt.from_ntt()
    ntt_error = np.max(np.abs(test_poly.coeffs - test_back.coeffs))
    print(f"  Max error after NTT round-trip: {ntt_error}")
    print(f"  NTT is {'CORRECT' if ntt_error == 0 else 'INCORRECT'}\n")
    
    # CBD sampling
    random_bytes = secrets.token_bytes(64 * 3)
    noisy_poly = centered_binomial_distribution(eta=3, random_bytes=random_bytes)
    print(f"CBD sample (first 10): {noisy_poly.coeffs[:10]}")
    small_positive = np.sum((noisy_poly.coeffs >= 0) & (noisy_poly.coeffs <= 3))
    small_negative = np.sum(noisy_poly.coeffs >= 3326)
    print(f"Distribution: {small_positive} small positive, {small_negative} small negative\n")
    
    # Matrix operations (with NTT)
    print("Matrix-vector multiplication test (with NTT):")
    seed = secrets.token_bytes(32)
    A = generate_matrix_from_seed(seed, k=2, transpose=False)  # A is in NTT domain
    s, _ = sample_noise_vector(k=2, eta=3, seed=secrets.token_bytes(32), nonce=0)
    s_hat = s.to_ntt()  # Convert s to NTT domain
    b = A.multiply_vector(s_hat)
    print(f"  Result: {b.k} polynomials in NTT domain\n")
    
    # Key generation
    params = kyber512_params()
    public_key, secret_key = kyber_keygen(params)
    print(f"Key generation complete:")
    print(f"  Public key: {len(public_key)} bytes")
    print(f"  Secret key (extended with H(pk) and z): {len(secret_key)} bytes\n")
    
    # Compression test
    test_poly = Polynomial(np.random.randint(0, 3329, 256), q=3329, is_ntt=False)
    test_poly_copy = Polynomial(test_poly.coeffs.copy(), q=3329, is_ntt=False)
    compress_poly(test_poly, d=4)
    decompress_poly(test_poly, d=4, q=3329)
    error = np.abs(test_poly_copy.coeffs - test_poly.coeffs)
    print(f"Compression test (d=4):")
    print(f"  Max error: {np.max(error)}")
    print(f"  Mean error: {np.mean(error):.2f}\n")
    
    # Full key exchange demonstration
    print("="*60)
    print("KEY EXCHANGE DEMONSTRATION (with FO Transform)")
    print("="*60)
    print()
    
    print("Bob: Generating keypair...")
    bob_public_key, bob_secret_key = kyber_keygen(params)
    print(f"  Bob's public key: {len(bob_public_key)} bytes")
    print(f"  Bob's secret key (extended): {len(bob_secret_key)} bytes")
    print()
    
    print("Alice: Encapsulating shared secret with Bob's public key...")
    alice_shared_secret, ciphertext = kyber_encapsulate(bob_public_key, params)
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"  Alice's shared secret: {alice_shared_secret.hex()[:32]}...")
    print()
    
    print("Bob: Decapsulating ciphertext with secret key...")
    bob_shared_secret = kyber_decapsulate(ciphertext, bob_secret_key, params)
    print(f"  Bob's shared secret: {bob_shared_secret.hex()[:32]}...")
    print()
    
    if alice_shared_secret == bob_shared_secret:
        print(" SUCCESS! Both parties have the same shared secret.")
        print("  Fujisaki-Okamoto transform ensures CCA security.")
        print("  They can now use this to encrypt communications.")
    else:
        print(" ERROR: Shared secrets don't match!")


if __name__ == "__main__":
    print("="*60)
    print("UNIFIED CRYPTOGRAPHY LIBRARY TESTS")
    print("="*60)
    
    print("\n" + "="*60)
    print("ECC (Elliptic Curve Cryptography) Tests")
    print("="*60)
    
    # Run ECC tests
    print("\nRunning ECC Tests...")
    
    # Initialize Curve
    curve = secp256k1()
    
    # 1. Test Generator
    assert curve.is_on_curve(curve.generator), "Generator should be on curve"
    
    # 2. Test Doubling vs Addition
    double_g = curve.double(curve.generator)
    add_g = curve.add(curve.generator, curve.generator)
    assert double_g == add_g, "Doubling should equal adding point to itself"
    assert curve.is_on_curve(double_g), "Doubled point should be on curve"
    
    # 3. Test Scalar Multiplication
    two_g = curve.scalar_mul(2, curve.generator)
    assert two_g == double_g, "Scalar mult by 2 should equal doubling"
    
    # 4. Test Key Exchange Simulation
    alice_priv = generate_private_key(curve)
    bob_priv = generate_private_key(curve)

    print(f"Alice Private Key: {alice_priv}")
    print(f"Bob Private Key: {bob_priv}")
    
    alice_pub = derive_public_key(curve, alice_priv)
    bob_pub = derive_public_key(curve, bob_priv)

    print(f"Alice Public Key: ({alice_pub.x}, {alice_pub.y})")
    print(f"Bob Public Key: ({bob_pub.x}, {bob_pub.y})")
    
    # Alice calculates shared secret using her Priv + Bob's Pub
    shared_alice = derive_shared_secret(curve, alice_priv, bob_pub)
    
    # Bob calculates shared secret using his Priv + Alice's Pub
    shared_bob = derive_shared_secret(curve, bob_priv, alice_pub)

    print(f"Shared Secret (Alice): ({shared_alice.x}, {shared_alice.y})")
    print(f"Shared Secret (Bob): ({shared_bob.x}, {shared_bob.y})")
    
    assert shared_alice == shared_bob, "Shared secrets must match"
    
    # 5. Test Key Derivation
    key_alice = point_to_shared_key(shared_alice)
    key_bob = point_to_shared_key(shared_bob)
    
    print(f"ECC Tests Passed!")
    print(f"Sample Shared Key (Hex): {key_alice.hex()}")
    
    # Run Kyber tests
    test_kyber()