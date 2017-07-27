from numpy import arange, array, ones
from numpy.linalg import lstsq

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
