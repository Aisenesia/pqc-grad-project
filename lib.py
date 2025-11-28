import secrets
import hashlib
from dataclasses import dataclass

# ============================================================================
# Finite Field Arithmetic Helpers
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
# Elliptic Curve Structures
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
# secp256k1 Initialization and Key Utils
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

# ============================================================================
# Tests (Runnable Block)
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