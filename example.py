from matplotlib.pylab import gca, figure, axes, plot, subplot, title, xlabel, ylabel, xlim, ylim, show
from matplotlib.lines import Line2D
#from matplotlib import pyplot as plt
import numpy as np
from numpy import arange, array, ones
from numpy.linalg import lstsq

from matplotlib import animation
import segment
import create_segment

def draw_plot(data, plot_title):
	plot(range(len(data)), data, alpha = 0.8, color = 'red')
	title(plot_title)
	xlabel("time")
	ylabel("signal")
	xlim((0, len(data) - 1))

def draw_segments(segments):
    ax = gca()
    for segment in segments:
        line = Line2D((segment[0],segment[2]),(segment[1],segment[3]))
        ax.add_line(line)

with open("./16265-normalecg.txt") as f:
	file_lines = f.readlines()

max_error = 0.005

data = [float(x.split("\t")[2].strip()) for x in file_lines[100:320]]

# online algorithm

if (len(data) % 2 == 1):
	data += [data[len(data) - 1]]

K = 20
rws = 5 # rws = Receiver Window Size
new_segment_data = []
segments = []
segment_error = []
merge_segments = []
merge_error = []

data_count = 0
while (data_count < len(data)):
	new_segment_data += [data[data_count]]
	data_count += 1
	if (data_count % rws == 0):
		""" 0 1 (data_count - 1) """
		x = arange(data_count - rws, data_count) 
		y = array(new_segment_data[0:rws])
		A = ones((len(x), 2), float)
		A[:,0] = x
		(p, residuals, rank, s) = lstsq(A, y)
		y0 = p[0] * (data_count - rws) + p[1]
		y1 = p[0] * (data_count - 1) + p[1]
		new_segment = (data_count - rws, y0, data_count - 1, y1)
		segments += [new_segment]
		del new_segment_data[:]
figure()
draw_plot(data, "online algorithm with K segments (K=20)")
draw_segments(segments)
show()

""""
fig = figure()
ax = axes(xlim=(0, len(data) - 1), ylim=(-10, 10))
line, = ax.plot([], [], lw=1.0)

# initialization function: plot the background of each frame
def init():
    line.set_data([], [])
    return line,

# animation function.  This is called sequentially
def animate(i):
    x = np.linspace(0, len(data) - 1, 100)
    y = np.sin(2 * np.pi * (x - 0.01 * i))
    line.set_data(x, y)
    return line,

# call the animator.  blit=True means only re-draw the parts that have changed.
anim = animation.FuncAnimation(fig, animate, init_func=init,
                               frames=100, interval=50, blit=False)
show()
"""

# offline approach
""""
figure()
draw_plot(data, "original data v.s. sliding-window-regression segmenting")
segment_regression = segment.sliding_window_segment(data, create_segment.regression, create_segment.sumsquared_error, max_error)
for seg in segment_regression:
	print seg[0], seg[2]
draw_segments(segment_regression)

figure()
draw_plot(data, "original data v.s. the top-down -regression segmenting")
segment_regression = segment.top_down_segment(data, create_segment.regression, create_segment.sumsquared_error, max_error)
for seg in segment_regression:
	print seg[0], seg[2]
draw_segments(segment_regression)


figure()
draw_plot(data, "original data v.s. the bottom-up -regression segmenting")
segment_regression = segment.bottom_up_segment(data, create_segment.regression, create_segment.sumsquared_error, max_error)
for seg in segment_regression:
	print seg[0], seg[2]
draw_segments(segment_regression)
show()
"""
