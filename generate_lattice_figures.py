"""
Generate Lattice Cryptography Figures for Academic Report
Creates visualizations of:
1. Good vs Bad Basis concept
2. Shortest Vector Problem (SVP)
3. Closest Vector Problem (CVP)
"""

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch
from matplotlib.patches import Circle
import matplotlib.patches as mpatches

# Set publication-quality parameters
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 11
plt.rcParams['text.usetex'] = False  # Set to True if LaTeX is installed
plt.rcParams['figure.dpi'] = 300

def generate_lattice_points(basis, range_n=5):
    """Generate lattice points from basis vectors"""
    points = []
    b1, b2 = basis
    for i in range(-range_n, range_n + 1):
        for j in range(-range_n, range_n + 1):
            point = i * b1 + j * b2
            points.append(point)
    return np.array(points)

def plot_good_vs_bad_basis():
    """Figure 1: Good Basis vs Bad Basis Concept"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Good basis: short, nearly orthogonal vectors
    good_b1 = np.array([1.0, 0.2])
    good_b2 = np.array([0.1, 1.0])
    good_basis = np.array([good_b1, good_b2])
    
    # Bad basis: long, highly skewed vectors (same lattice!)
    # These are integer linear combinations of the good basis
    bad_b1 = 3 * good_b1 + 2 * good_b2  # [3.2, 2.6]
    bad_b2 = 2 * good_b1 + 2 * good_b2  # [2.2, 2.4]
    bad_basis = np.array([bad_b1, bad_b2])
    
    # Generate lattice points ONCE using good basis - both plots show SAME points
    lattice_points = generate_lattice_points(good_basis, range_n=4)
    
    # Plot Good Basis - SAME POINTS
    ax1.scatter(lattice_points[:, 0], lattice_points[:, 1], 
                c='#2E86AB', s=30, alpha=0.6, zorder=2)
    ax1.scatter([0], [0], c='red', s=80, marker='o', zorder=3, label='Origin')
    
    # Draw basis vectors
    ax1.annotate('', xy=good_b1, xytext=(0, 0),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='#A23B72'))
    ax1.annotate('', xy=good_b2, xytext=(0, 0),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='#F18F01'))
    
    ax1.text(good_b1[0]/2, good_b1[1]/2 - 0.3, r'$\mathbf{b}_1$', 
             fontsize=14, fontweight='bold', color='#A23B72')
    ax1.text(good_b2[0]/2 - 0.3, good_b2[1]/2, r'$\mathbf{b}_2$', 
             fontsize=14, fontweight='bold', color='#F18F01')
    
    ax1.grid(True, alpha=0.3, linestyle='--')
    ax1.set_xlim(-5, 5)
    ax1.set_ylim(-5, 5)
    ax1.set_aspect('equal')
    ax1.set_title('(a) Good Basis\n(Short, Nearly Orthogonal)', fontsize=12, fontweight='bold')
    ax1.set_xlabel('x', fontsize=11)
    ax1.set_ylabel('y', fontsize=11)
    
    # Plot Bad Basis - SAME POINTS (identical to left plot)
    ax2.scatter(lattice_points[:, 0], lattice_points[:, 1], 
                c='#2E86AB', s=30, alpha=0.6, zorder=2)
    ax2.scatter([0], [0], c='red', s=80, marker='o', zorder=3, label='Origin')
    
    # Draw basis vectors (different basis, same lattice!)
    ax2.annotate('', xy=bad_b1, xytext=(0, 0),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='#A23B72'))
    ax2.annotate('', xy=bad_b2, xytext=(0, 0),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='#F18F01'))
    
    ax2.text(bad_b1[0]/2 - 0.5, bad_b1[1]/2, r"$\mathbf{b}'_1$", 
             fontsize=14, fontweight='bold', color='#A23B72')
    ax2.text(bad_b2[0]/2, bad_b2[1]/2 - 0.5, r"$\mathbf{b}'_2$", 
             fontsize=14, fontweight='bold', color='#F18F01')
    
    ax2.grid(True, alpha=0.3, linestyle='--')
    ax2.set_xlim(-5, 5)  # SAME limits as left plot
    ax2.set_ylim(-5, 5)  # SAME limits as left plot
    ax2.set_aspect('equal')
    ax2.set_title('(b) Bad Basis\n(Long, Highly Skewed)', fontsize=12, fontweight='bold')
    ax2.set_xlabel('x', fontsize=11)
    ax2.set_ylabel('y', fontsize=11)
    
    plt.tight_layout()
    plt.savefig('Tex/Imgs/lattice_good_vs_bad_basis.png', bbox_inches='tight', dpi=300)
    print("✓ Generated: lattice_good_vs_bad_basis.png")
    plt.close()

def plot_svp_cvp():
    """Figure 2: Shortest Vector Problem and Closest Vector Problem"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Define basis
    b1 = np.array([2.0, 0.5])
    b2 = np.array([0.3, 1.8])
    basis = np.array([b1, b2])
    
    # Generate lattice points
    points = generate_lattice_points(basis, range_n=3)
    
    # Calculate distances from origin for SVP
    distances = np.linalg.norm(points, axis=1)
    non_zero_mask = distances > 0.01
    shortest_idx = np.where(non_zero_mask)[0][np.argmin(distances[non_zero_mask])]
    shortest_vector = points[shortest_idx]
    
    # SVP Plot
    ax1.scatter(points[:, 0], points[:, 1], 
                c='#2E86AB', s=40, alpha=0.5, zorder=2, label='Lattice Points')
    ax1.scatter([0], [0], c='red', s=100, marker='o', zorder=3, label='Origin')
    ax1.scatter([shortest_vector[0]], [shortest_vector[1]], 
                c='#C73E1D', s=150, marker='*', zorder=4, 
                edgecolors='black', linewidth=1.5, label='Shortest Vector')
    
    # Draw shortest vector
    ax1.annotate('', xy=shortest_vector, xytext=(0, 0),
                arrowprops=dict(arrowstyle='->', lw=3, color='#C73E1D'))
    
    # Draw circle showing distance
    circle = Circle((0, 0), np.linalg.norm(shortest_vector), 
                   fill=False, color='#C73E1D', linestyle='--', 
                   linewidth=2, alpha=0.6, label='Distance')
    ax1.add_patch(circle)
    
    ax1.grid(True, alpha=0.3, linestyle='--')
    ax1.set_xlim(-7, 7)
    ax1.set_ylim(-7, 7)
    ax1.set_aspect('equal')
    ax1.set_title('(a) Shortest Vector Problem (SVP)\nFind shortest non-zero vector', 
                  fontsize=12, fontweight='bold')
    ax1.set_xlabel('x', fontsize=11)
    ax1.set_ylabel('y', fontsize=11)
    ax1.legend(loc='upper right', fontsize=9)
    
    # CVP Plot
    # Target point (not on lattice) - positioned for better visibility
    target = np.array([3.2, 2.8])
    
    # Find closest lattice point
    distances_to_target = np.linalg.norm(points - target, axis=1)
    closest_idx = np.argmin(distances_to_target)
    closest_point = points[closest_idx]
    
    # Only show points in relevant region for clarity
    relevant_mask = (np.abs(points[:, 0]) < 6) & (np.abs(points[:, 1]) < 6)
    relevant_points = points[relevant_mask]
    
    ax2.scatter(relevant_points[:, 0], relevant_points[:, 1], 
                c='#2E86AB', s=60, alpha=0.5, zorder=2, label='Lattice Points')
    ax2.scatter([target[0]], [target[1]], 
                c='#F18F01', s=200, marker='X', zorder=4,
                edgecolors='black', linewidth=1.5, label='Target Point')
    ax2.scatter([closest_point[0]], [closest_point[1]], 
                c='#06A77D', s=200, marker='*', zorder=4,
                edgecolors='black', linewidth=1.5, label='Closest Lattice Point')
    
    # Draw line from target to closest point
    ax2.plot([target[0], closest_point[0]], 
             [target[1], closest_point[1]], 
             'r--', linewidth=3, alpha=0.7, label='Distance')
    
    # Draw circle showing search region
    circle2 = Circle(target, np.linalg.norm(target - closest_point), 
                    fill=False, color='#F18F01', linestyle=':', 
                    linewidth=2, alpha=0.5)
    ax2.add_patch(circle2)
    
    ax2.grid(True, alpha=0.3, linestyle='--')
    ax2.set_xlim(-1, 7)  # Zoomed in on relevant region
    ax2.set_ylim(-1, 7)
    ax2.set_aspect('equal')
    ax2.set_title('(b) Closest Vector Problem (CVP)\nFind lattice point nearest to target', 
                  fontsize=12, fontweight='bold')
    ax2.set_xlabel('x', fontsize=11)
    ax2.set_ylabel('y', fontsize=11)
    ax2.legend(loc='upper left', fontsize=9)
    
    plt.tight_layout()
    plt.savefig('Tex/Imgs/lattice_svp_cvp.png', bbox_inches='tight', dpi=300)
    print("✓ Generated: lattice_svp_cvp.png")
    plt.close()

def plot_same_lattice_proof():
    """Figure 3: Proof that good and bad basis generate same lattice"""
    fig, ax = plt.subplots(1, 1, figsize=(8, 8))
    
    # Good basis
    good_b1 = np.array([1.0, 0.2])
    good_b2 = np.array([0.1, 1.0])
    good_basis = np.array([good_b1, good_b2])
    
    # Bad basis (linear combination of good basis)
    # b1' = 3*b1 + 2*b2, b2' = 2*b1 + 2*b2
    bad_b1 = 3 * good_b1 + 2 * good_b2
    bad_b2 = 2 * good_b1 + 2 * good_b2
    
    # Generate points
    points = generate_lattice_points(good_basis, range_n=4)
    
    # Plot lattice
    ax.scatter(points[:, 0], points[:, 1], 
               c='#2E86AB', s=50, alpha=0.6, zorder=2, label='Lattice Points')
    ax.scatter([0], [0], c='red', s=100, marker='o', zorder=3)
    
    # Draw both basis sets
    ax.annotate('', xy=good_b1, xytext=(0, 0),
               arrowprops=dict(arrowstyle='->', lw=2.5, color='#A23B72', alpha=0.7))
    ax.annotate('', xy=good_b2, xytext=(0, 0),
               arrowprops=dict(arrowstyle='->', lw=2.5, color='#F18F01', alpha=0.7))
    
    ax.annotate('', xy=bad_b1, xytext=(0, 0),
               arrowprops=dict(arrowstyle='->', lw=2.5, color='#A23B72', 
                             linestyle='--', alpha=0.7))
    ax.annotate('', xy=bad_b2, xytext=(0, 0),
               arrowprops=dict(arrowstyle='->', lw=2.5, color='#F18F01', 
                             linestyle='--', alpha=0.7))
    
    # Labels
    ax.text(good_b1[0]/2, good_b1[1]/2 - 0.3, r'$\mathbf{b}_1$', 
            fontsize=14, fontweight='bold', color='#A23B72')
    ax.text(good_b2[0]/2 - 0.3, good_b2[1]/2, r'$\mathbf{b}_2$', 
            fontsize=14, fontweight='bold', color='#F18F01')
    ax.text(bad_b1[0]/2 - 0.3, bad_b1[1]/2 + 0.3, r"$\mathbf{b}'_1$", 
            fontsize=14, fontweight='bold', color='#A23B72')
    ax.text(bad_b2[0]/2 + 0.2, bad_b2[1]/2 - 0.2, r"$\mathbf{b}'_2$", 
            fontsize=14, fontweight='bold', color='#F18F01')
    
    # Create legend
    solid_line = mpatches.Patch(color='purple', label='Good Basis (solid)')
    dashed_line = mpatches.Patch(color='purple', label='Bad Basis (dashed)')
    ax.legend(handles=[solid_line, dashed_line], loc='upper right', fontsize=10)
    
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.set_xlim(-5, 6)
    ax.set_ylim(-5, 6)
    ax.set_aspect('equal')
    ax.set_title('Both Bases Generate the Same Lattice\n' + 
                r"$\mathbf{b}'_1 = 3\mathbf{b}_1 + 2\mathbf{b}_2$, " +
                r"$\mathbf{b}'_2 = 2\mathbf{b}_1 + 2\mathbf{b}_2$",
                fontsize=12, fontweight='bold')
    ax.set_xlabel('x', fontsize=11)
    ax.set_ylabel('y', fontsize=11)
    
    plt.tight_layout()
    plt.savefig('Tex/Imgs/lattice_same_lattice.png', bbox_inches='tight', dpi=300)
    print("✓ Generated: lattice_same_lattice.png")
    plt.close()

if __name__ == "__main__":
    print("Generating lattice cryptography figures...")
    print("-" * 50)
    
    plot_good_vs_bad_basis()
    plot_svp_cvp()
    plot_same_lattice_proof()
    
    print("-" * 50)
    print("All figures generated successfully!")
    print("\nFigures saved to: Tex/Imgs/")
    print("  - lattice_good_vs_bad_basis.png")
    print("  - lattice_svp_cvp.png")
    print("  - lattice_same_lattice.png")
