# algorithm that segments time series 

def online_segment(new_segment, segments, segment_number, merge_segments, merge_error, max_error):
	if (len(segments) == 0):
		segments += [new_segment]
	elif (len(segments) < segment_number):
		segments += [new_segment]
		#merge_segments += 
	elif (len(segments == segment_number)):
		# merge and delete
		return
	else:
		print "Error!"
	return

def sliding_window_segment(sequence, create_segment, compute_error, max_error, seq_range=None):
	if (seq_range == None):
		seq_range = (0, len(sequence) - 1)

	start = seq_range[0]
	end = start
	result_segment = create_segment(sequence, (seq_range[0], seq_range[1]))
	while(end < seq_range[1]):
		end += 1
		segment = create_segment(sequence, (start, end))
		error = compute_error(sequence, segment)
		if (error <= max_error):
			result_segment = segment
		else:
			break
	if (end == seq_range[1]):
		return [result_segment]
	else:
		return [result_segment] + sliding_window_segment(sequence, create_segment, compute_error, max_error, (end, seq_range[1]))

def top_down_segment(sequence, create_segment, compute_error, max_error, seq_range=None):
	if (seq_range == None):
		seq_range = (0, len(sequence) - 1)

	start = seq_range[0]
	end = seq_range[1]
	midpoint = start + 1

	best_left_error = float('inf')
	best_right_error = float('inf')
	best_so_far = float('inf')
	breakpoint = midpoint
	while (midpoint < end):
		left_segment = create_segment(sequence, (start, midpoint))
		left_error = compute_error(sequence, left_segment)
		right_segment = create_segment(sequence, (midpoint + 1, end))
		right_error = compute_error(sequence, right_segment)
		cur_error = left_error + right_error
		if (cur_error < best_so_far):
			breakpoint = midpoint
			best_so_far = cur_error
			best_left_error = left_error
			best_right_error = right_error
			best_left_segment = left_segment
			best_right_segment = right_segment
		midpoint += 1

	if (best_left_error > max_error):
		left_segments = top_down_segment(sequence, create_segment, compute_error, max_error, (start, breakpoint))
	else:
		left_segments = [best_left_segment]

	if (best_right_error > max_error):
		right_segments = top_down_segment(sequence, create_segment, compute_error, max_error, (breakpoint + 1, end))
	else:
		right_segments = [best_right_segment]

	return left_segments + right_segments


def bottom_up_segment(sequence, create_segment, compute_error, max_error, seq_range=None):
	if (len(sequence) % 2 == 1):
		sequence += [sequence[len(sequence) - 1]]

	segments = [create_segment(sequence, seq_range) for seq_range in zip(range(len(sequence))[::2], range(len(sequence) + 1)[1::2] )]
	merge_segments = [create_segment(sequence, (seq_0[0], seq_1[2])) for seq_0, seq_1 in zip( segments[:-1], segments[1:] )]
	merge_error = [compute_error(sequence, seq) for seq in merge_segments]

	while (min(merge_error) < max_error):
		index = merge_error.index(min(merge_error))
		segments[index] = merge_segments[index]
		del segments[index + 1]
		if index > 0:
			merge_segments[index - 1] = create_segment(sequence, (segments[index - 1][0], segments[index][2]))
			merge_error[index - 1] = compute_error(sequence, merge_segments[index - 1])
		if index + 1 < len(merge_segments):
			merge_segments[index + 1] = create_segment(sequence, (segments[index][0], segments[index + 1][2]))
			merge_error[index + 1] = compute_error(sequence, merge_segments[index + 1])
		del merge_segments[index]
		del merge_error[index]
	return segments

