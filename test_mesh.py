import sys
sys.path.insert(0, '/home/soniya/noxim')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from app import render_5x5_mesh

fig = render_5x5_mesh(12, 13)
fig.savefig('/home/soniya/noxim/test_mesh.png', bbox_inches='tight', dpi=140)
plt.close(fig)
print('Mesh rendered OK')
