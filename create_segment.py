from numpy import arange, array, ones
from numpy.linalg import lstsq

# compute_error functions

def compute_error(time, sequence, length):
	#time_0, seq_0, time_1, seq_1 = segment
	p, error = least_squares_linear_fit(time, sequence, length)
	return error

def sumsquared_error(sequence, segment):
	x0, y0, x1, y1 = segment
	p, error = leastsquareslinefit(sequence, (x0, x1))
	return error

def regression_X_on_Y(time, sequence, length):
	p, error = least_squares_linear_fit(time, sequence, length)
	time_0 = p[0] * sequence[0] + p[1]
	time_1 = p[0] * sequence[length - 1] + p[1]
	return (time_0, sequence[0], time_1, sequence[length - 1])

def regression(sequence, seq_range):
	p, error = leastsquareslinefit(sequence, seq_range)
	y0 = p[0] * seq_range[0] + p[1]
	y1 = p[0] * seq_range[1] + p[1]
	return (seq_range[0], y0, seq_range[1], y1)
""""
	linear interpolation method
"""
def interpolate(sequence, seq_range):
	return (seq_range[0], sequence[seq_range[0]], seq_range[1], sequence[seq_range[1]])

"""
	This function returns the parameters and error for a least square line fit of one 'segment'
	of a time-sequence number plot.
	Estimated time = p[0] * (Sequence number) + p[1]
"""
def least_squares_linear_fit(time, sequence, length):
    x = sequence[0: length]
    y = time[0: length]
    A = ones((len(x), 2), int)
    A[:, 0] = x
    (p, residuals, rank, s) = lstsq(A, y)
    try:
        error = residuals[0]
    except IndexError:
        error = 0.0
    return (p, error)

def leastsquareslinefit(sequence,seq_range):
    """Return the parameters and error for a least squares line fit of one segment of a sequence"""
    x = arange(seq_range[0],seq_range[1]+1)
    y = array(sequence[seq_range[0]:seq_range[1]+1])
    A = ones((len(x),2),float)
    A[:,0] = x
    (p,residuals,rank,s) = lstsq(A,y)
    try:
        error = residuals[0]
    except IndexError:
        error = 0.0
    return (p,error)
