from numpy import arange, array, ones
from numpy.linalg import lstsq

def least_squares_linear_fit(time, sequence, length):
	"""
		Return the parameters and error for a least squares line fit of one segment
		of a sequence
	"""

	x = time[0:length]
	y = sequence[0:length]

	A = ones((len(x),2), float)
	A[:,0] = x
	(p, residuals, rank, s) = lstsq(A, y)
	try:
		error = residuals[0]
	except IndexError:
		error = 0.0
	return (p, error)

def interpolate(time, sequence):
	return (time[0], sequence[0], time[len(time)-1], sequence[len(sequence)-1])


def sumsquared_error(time, sequence, length):
	"""
		Return the sum of squared errors for a least squared line fit of one segment of a sequence
	"""
	p, error = least_squares_linear_fit(time, sequence, length)
	return error


def get_compressed_plot(current_segment, create_segment, compute_error, max_error):
	# 1. Get the list of uncompressed list
	# current_segment_time = [time_list]
	# current_segment_sequence = [sequence_list]
	current_segment_time = []
	current_segment_sequence = []
	for packet in current_segment:
		current_segment_time.append(packet.timestamp_us)
		current_segment_sequence.append(packet.seq)

	# 2. The sliding window segmentation algorithm
	# Return: result_nodes (a list of nodes)

	result_nodes = []
	result_nodes += [[current_segment[0], 0]]

	result_times = []
	result_sequences = []

	result_segment = None

	time = []
	sequence = []
	length = 0
	index = 0

	while (index < len(current_segment_time)):

		time.append(current_segment_time[index])
		sequence.append(current_segment_sequence[index])
		length += 1
		if length <= 2:
			index += 1
			continue

		error = sumsquared_error(time, sequence, length)

		if error < max_error:
			index += 1
			continue
		else:

			result_nodes += [[current_segment[index-1], length-1]]
			index = index-1
			time = []
			sequence = []
			length = 0
			error = 0

	if length != 0:
		result_nodes += [[current_segment[index-1], length]]

	return result_nodes


