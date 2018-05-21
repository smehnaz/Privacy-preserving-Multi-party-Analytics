"""
	Implements some simple operations for matrices. Numpy/scipy would be better.

        @Arlei Silva, arlei.lopes-da-siva@hp.com
	Last change:
"""

def matrix_zeros_3D(x, y, z):
	"""
		Creates a 3D matrix of 0s
	"""
	m = []
	for i in range(x):
		m.append([])
		for j in range(y):
			m[-1].append([])
			for k in range(z):
				m[-1][-1].append(0)
	return m
 
def matrix_zeros_2D(x, y):
	"""
		Creates a 2D matrix of 0s
	"""
	m = []
	for i in range(x):
		m.append([])
		for j in range(y):
			m[-1].append(0)
	
	return m

def slice_matrix_z(M, z):
	"""
		Returns a z slice (x,y,x) of a 3D matrix
	"""
	S = []

	for i in range(len(M)):
		S.append([])
		for j in range(len(M[0])):
			S[-1].append(M[i][j][z])

	return S

def slice_matrix_j(M, j):
	"""
		Returns a column of a matrix
	"""
	S = []

	for i in range(len(M)):
		S.append(M[i][j])

	return S

def transpose_3D_matrix(M):
	"""
		Transposes a 3D matrix. (x,y,z) => (y,z,x)
	"""
	Q = matrix_zeros_3D(len(M[0]), len(M[0][0]), len(M))

	for i in range(len(M)):
		for j in range(len(M[0])):
			for k in range(len(M[0][0])):
				Q[j][k][i] = M[i][j][k]

	return Q

def transpose_2D_matrix(M):
	"""
		Transposes a 2D matrix
	"""
	Q = matrix_zeros_2D(len(M[0]), len(M))

	for i in range(len(M)):
		for j in range(len(M[0])):
			Q[j][i] = M[i][j]

	return Q

