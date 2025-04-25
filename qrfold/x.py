import sympy, cv2, numpy as np

# this generates an image that can be printed out and folded into a 90 degree corner with forced perspective

t1,t2 = sympy.symbols('t1,t2')

l = 3 # perspective length (ratio of optimal viewing distance to qr code size)

m = sympy.rot_axis1(t1) * sympy.rot_axis2(t2) * sympy.rot_axis3(sympy.pi / 8) # the transformation matrix of the camera - the view matrix
m2 = sympy.rot_axis1(sympy.pi / 10) # the transformation matrix of the qr code - make it look skewed at the correct perspective

c = sympy.Matrix([0, 0.2, l]) # the x and y components are a center offset for the image
a = [m2 * sympy.Matrix([s1, s2, 0]) + sympy.Matrix([0, 0, -l]) for s1 in [-1, 1] for s2 in [-1, 1]]

mc = m * c
ma = [m * a for a in a]

c2=mc.replace(t1, sympy.pi / 4).replace(t2, -sympy.atan(sympy.sqrt(2) / 2))
a2=[ma.replace(t1, sympy.pi / 4).replace(t2, -sympy.atan(sympy.sqrt(2) / 2)) for ma in ma]

t = sympy.symbols('t')

x=[c2+t*a for a in a2]

def a1(l):
 x, = l
 return x

x2 = [[sympy.N(a1(sympy.linsolve([x[i][j]], t))[0]) for i in range(4)] for j in range(3)]

sols = [[x[i].replace(t, a1(sympy.linsolve([x[i][j]], t))[0]) for i in range(4)] for j in range(3)]

im = cv2.imread(r'Screenshot (102).png', cv2.IMREAD_UNCHANGED)

sols2 = [[[float(sympy.N(v)) for v in x] for x in r] for r in sols]

def rem(l, i):
 l[i:i + 1] = []

def add(l,i):
 l2=[*l]
 l2[i:i]= []
 return l2

[[rem(x, i) for x in r] for i,r in enumerate(sols2)]

src = im

def rem(l, i):
 l[i:i + 1] = []

size = 300

ims = []

factor = max([c for a in sols2 for b in a for c in b])

for i in range(3):
 sol = sols2[i]
 #print(sol)
 dst_pts = np.array([[size * p[1] / factor, size * p[0] / factor] for p in sol])
 src_pts = np.array([[0, 0], [src.shape[1], 0], [0, src.shape[0]], [src.shape[1], src.shape[0]]], dtype = np.float64)
 H, _ = cv2.findHomography(src_pts, dst_pts, 0)
 #print(H)
 #for p,dp in zip(src_pts,dst_pts):
  #x,y,z = np.array(H)@np.array([*p, 1])
  #print(x/z,y/z,dp)
 warped = cv2.warpPerspective(src, H, (size, size))
 ims.append(warped)
 #cv2.imshow('Result', warped)
 #cv2.waitKey(0)
 #cv2.destroyAllWindows()
 #cv2.imwrite(f'im{i}.png', warped)

blank_img = np.zeros(shape=(size * 2, size * 2, 4), dtype=np.uint8)

blank_img[:size, :size] = ims[0][::-1, ::-1]
blank_img[size:, :size] = ims[1][:, ::-1]
blank_img[:size, size:] = np.swapaxes(ims[2][:, ::-1], 0, 1)
cv2.imshow('Result', blank_img)
cv2.waitKey(0)
cv2.destroyAllWindows()

cv2.imwrite('persp-qr.png', blank_img)
