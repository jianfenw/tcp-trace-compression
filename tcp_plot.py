from matplotlib.pylab import gca, figure, axes, plot, scatter, subplot, title, xlabel, ylabel, xlim, ylim, show
from matplotlib.lines import Line2D
import numpy as np
from numpy import arange, array, ones
from numpy.linalg import lstsq

import dpkt
from tcp_endpoint import *
from tcp_flow import *
from tcp_util import *

# Minimum number of samples (data points) for each loss/pass category
# to enable detection of policing with confidence
MIN_NUM_SAMPLES = 15

# Minimum number of RTT slices seeing loss to enable detection
# of policing with confidence
MIN_NUM_SLICES_WITH_LOSS = 3

# Maximum relative sequence number acceptable for the first loss
LATE_LOSS_THRESHOLD = 2E6

# Number of RTTs used to compute the number of tokens allowed in the bucket when observing
# packet loss to infer policing. The allowed fill level is computed by multiplying the
# estimated policing rate with a multiple of the median RTT. The
# multiplier is specified here.
ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.00
ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75

# Fraction of cases allowed to have a number of tokens available on loss
# larger than the computed zero threshold
ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.40
ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.53

ZERO_THRESHOLD_LOSS_OUT_OF_TOTAL_RANGE = 0.20
ZERO_THRESHOLD_PASS_OUT_OF_TOTAL_RANGE = 0.03

# Percentile of the RTT samples used to compute the inflation threshold
INFLATED_RTT_PERCENTILE = 10

# Fraction of the Xth percentile RTT beyond which an RTT sample is
# considered inflated
INFLATED_RTT_THRESHOLD = 1.3

# Fraction of cases allowed to have inflated RTTs without ruling out
# a policer presence
INFLATED_RTT_TOLERANCE = 0.2

# Detection return codes
# All conditions for policing detection were met
RESULT_OK = 0

# Trace does not have enough loss (either absolute number of loss samples, or
# RTT slices with loss)
RESULT_INSUFFICIENT_LOSS = 1

# First loss appeared too late in the connection
RESULT_LATE_LOSS = 2

# Estimated token bucket fill would be negative at the beginning of the
# connection
RESULT_NEGATIVE_FILL = 3

# Estimated token bucket fill was higher when packets are lost compared to when
# packets passed through
RESULT_HIGHER_FILL_ON_LOSS = 4

# Estimated token bucket fill was out of range too often.
# For lost packets, the token bucket is estimated to be empty
# For passing packets, the token bucket is estimated to be filled
RESULT_LOSS_FILL_OUT_OF_RANGE = 5
RESULT_PASS_FILL_OUT_OF_RANGE = 6

# A significant fraction of losses is preceded by inflated RTTs (indicating other
# potential causes for loss, e.g. congestion)
RESULT_INFLATED_RTT = 7


def segment_recovery(loss_segment_flag, first_node, last_node, packet_num):
    segment_packets = [first_node]

    if packet_num > 1:
        inter_time = (last_node.timestamp_us - first_node.timestamp_us) / (packet_num - 1)
        inter_seq = (last_node.seq - first_node.seq) / (packet_num - 1)
        inter_bytes = (last_node.bytes_passed - first_node.bytes_passed) / (packet_num - 1)

        for i in range(1, packet_num):
            inter_node = TcpNode()
            inter_node.packet_segment_approximation(loss_segment_flag, first_node, i, inter_time, inter_seq, inter_bytes)
            segment_packets.append(inter_node)

        #print packet_num, segment_packets[len(segment_packets)-1].timestamp_us, last_node.timestamp_us, first_node.timestamp_us,inter_time
    else:
        #print packet_num, first_node.timestamp_us
        return segment_packets

    return segment_packets


class TcpNode(object):
    def __init__(self):
        #annotated_packet, time_base, appr=False, index=0, first=0, end=0):
        self.timestamp_us = 0
        self.seq = 0
        
        self.rtx = None
        self.rtt_ms = -1
        self.index = -1
        self.ack_index = -1
        self.is_lost = False
        self.data_len = 0

        self.bytes_passed = -1
        self.accumulative_lost_packet_count = -1
        self.cont_state_packet_number = -1
        
    def packet_node_converter(self, annotated_packet, time_base):
        self.timestamp_us = annotated_packet.timestamp_us - time_base
        self.seq = annotated_packet.seq_relative
        self.rtx = annotated_packet.rtx
        self.rtt_ms = annotated_packet.ack_delay_ms
        self.is_lost = annotated_packet.is_lost()
        self.data_len = annotated_packet.data_len
        self.index = annotated_packet.index
        self.ack_index = annotated_packet.ack_index
        self.bytes_passed = annotated_packet.bytes_passed

    def packet_segment_approximation(self, loss_segment, first_node, index, inter_time, inter_seq, inter_bytes):
        self.timestamp_us = first_node.timestamp_us + inter_time * index
        self.seq = first_node.seq + inter_seq * index
        '''
        if loss_segment:
            self.bytes_passed = first_node.bytes_passed
        else:
            self.bytes_passed = first_node.bytes_passed + inter_bytes * index
        '''
        self.bytes_passed = first_node.bytes_passed + inter_bytes * index

class TcpRTTPlot(object):
    def __init__(self, TcpPlot, size=0):
        # rtts = the rtt time in (ms)
        self.rtts = []
        self.rtts_number = 0
        self.loss_event_size = size

        self.median_rtt_ms = -1
        self.median_rtt_on_loss_ms = -1

        self.rtts_before_loss = [[],[],[],[],[]]
        self.rtts_after_loss = [[],[],[],[],[]]

        # Init Process
        # If packet is lost, the RTT time = 0.
        # If packet does not need to be ACKed, the RTT time = -1.
        for node in TcpPlot.uncompress_nodes:
            self.rtts_number += 1
            if node.is_lost:
                self.rtts.append(0)
            else:
                self.rtts.append(node.rtt_ms)

        # Process each loss event if self.rtts[j] == 0 or self.rtts[j] == -1:
        i = 0
        while (i <= self.rtts_number - 1):
            if self.rtts[i] == 0:
                #print i
                # A loss event has been found. i is the start of a loss event

                # Fill the packet bucket: rtts_before_loss
                for m in range(5):
                    if i-m-1 >= 0 and self.rtts[i-m-1] > 0:
                        self.rtts_before_loss[m].append(self.rtts[i-m-1])
                    else:
                        break

                count = 0
                prev_loss = i

                if prev_loss == self.rtts_number-1:
                    break
                j = 0

                for j in range(i+1, self.rtts_number):
                    if self.rtts[j] <= 0:
                        prev_loss = j
                        count = 0
                        continue
                    else:
                        # In this case, self.rtts[j] > 0 (the packet is not lost)
                        count += 1
                        if count >= self.loss_event_size + 1:
                            break
                i = prev_loss

                for m in range(5):
                    if i+m+1 <= self.rtts_number-1 and self.rtts[i+m+1] > 0:
                        self.rtts_after_loss[m].append(self.rtts[i+m+1])
                    else:
                        break
                i = j + 1
            else:
                i = i + 1

        """
        for i in reversed(range(self.rtts_number)):
            if self.rtts[i] == 0:
                if i + 1 <= self.rtts_number - 1 and self.rtts[i + 1] == 0:
                    continue

                for j in range(5):
                    if i+j+1 <= self.rtts_number-1 and self.rtts[i+j+1] != 0 and self.rtts[i+j+1] != -1:
                        self.rtts_after_loss[j].append(self.rtts[i+j+1])
                    else:
                        break
        """
    '''
    def get_median_rtts(self):

        result_list = [self.get_median_rtt_ms(self.rtts)]

        for i in range(5):
            tmp_result = [self.get_median_rtt_ms(self.rtts_before_loss[i]), \
                self.get_median_rtt_ms(self.rtts_after_loss[i])]

            result_list.append(tmp_result)

        return result_list
    '''

    def get_statistics_rtts(self):
        
        median_rtt = self.get_median_rtt_ms(self.rtts)
        mean_rtt = self.get_mean_rtt_ms(self.rtts)
        dev_rtt = 0
        
        median_before = [0 for i in range(5)]
        median_after = [0 for i in range(5)]
        mean_before = [0 for i in range(5)]
        mean_after = [0 for i in range(5)]
        dev_before = [0 for i in range(5)]
        dev_after = [0 for i in range(5)]

        for i in range(5):
            median_before[i] = median(self.rtts_before_loss[i])
            median_after[i] = median(self.rtts_after_loss[i])

            mean_before[i] = mean(self.rtts_before_loss[i])
            mean_after[i] = mean(self.rtts_after_loss[i])

            dev_before[i] = stan_deviation(self.rtts_before_loss[i])
            dev_after[i] = stan_deviation(self.rtts_after_loss[i])

        #print self.rtts_before_loss[0], median(self.rtts_before_loss[0])
        #print self.rtts_before_loss[1], median(self.rtts_before_loss[1])
        #print median_before, median_after
        #print mean_before, mean_after

        result_list = [median_rtt, mean_rtt, dev_rtt, median_before, median_after, \
            mean_before, mean_after, dev_before, dev_after]

        return result_list

    # The RTT for lost packets is +Inf.
    # The RTT for ACK packetes is -1.
    def get_rtts_number(self):
        count = 0
        for i in range(self.rtts_number):
            if self.rtts[i] != -1:
                count += 1
        return count

    def show_rtts_plot(self, plot_title, ident_color):
        figure()
        max_rtt = 0
        print self.rtts_number
        x_index = range(self.rtts_number)
        for index in x_index:
            if self.rtts[index] > max_rtt:
                max_rtt = self.rtts[index]
        scatter(x_index, self.rtts, s = 5, color = ident_color)
        title(plot_title)
        xlabel("Packet Index")
        ylabel("RTT times")
        xlim(0, x_index[len(x_index) - 1] + 10)
        ylim(0, max_rtt * 1.2)

    def get_median_rtt_ms(self, rtts_list):
        if self.median_rtt_ms != -1:
            return self.median_rtt_ms

        tmp_rtts = []
        for rtt in rtts_list:
            if rtt != -1 and rtt != 0:
                tmp_rtts.append(rtt)

        if len(tmp_rtts) >= 1:
            self.median_rtt_ms = median(tmp_rtts)
        else:
            self.median_rtt_ms = -1
        return self.median_rtt_ms

    def get_mean_rtt_ms(self, rtts_list):
        tmp_rtts = []
        for rtt in rtts_list:
            if rtt != -1 and rtt != 0:
                tmp_rtts.append(rtt)

        if len(tmp_rtts) >= 1:
            return mean(tmp_rtts)
        else:
            return -1

    """
        If the number of inflated rtts exceeds our threshold,
        inflated_rtt_flag will be set to '1'.
        In this case, traffic policing does not exist in this flow.

        Prediction Error = measured RTT - prediction
        New RTT estimation = old prediction + 1/8 * measured RTT
    """
    def get_inflated_rtt_flag(self):
        rtt_count_on_loss = 0
        inflated_rtt_count_on_loss = 0

        tmp_rtts = []

        for i in range(self.rtts_number):
            if self.rtts[i] != -1 and self.rtts[i] != 0:
                tmp_rtts.append(self.rtts[i])

            # The total number of losses which are token into consideration.
            if self.rtts[i] == 0:
                rtt_count_on_loss += 1

                if len(tmp_rtts) > 1 and tmp_rtts[-2] >= percentile(tmp_rtts, 50) \
                    and tmp_rtts[-2] > percentile(tmp_rtts, INFLATED_RTT_PERCENTILE) * \
                    INFLATED_RTT_THRESHOLD \
                    and tmp_rtts[-2] >= 20:
                    inflated_rtt_count_on_loss += 1

        if rtt_count_on_loss == 0:
            return -1
        else:
            return (inflated_rtt_count_on_loss / rtt_count_on_loss * 100)

        rtt_threshold = INFLATED_RTT_TOLERANCE * rtt_count_on_loss
        if inflated_rtt_count_on_loss > rtt_threshold:
            return 1

        return 0

        # Prediction Error = measured RTT - prediction
        # New RTT estimation = old prediction + 1/8 * measured RTT
    def get_inflated_rtt_flag_com(self):
        rtt_count_on_loss = 0
        inflated_rtt_count_on_loss = 0

        if self.get_rtts_number() <= 2:
            return None

        median_rtt_ms = self.get_median_rtt_ms(self.rtts)

        for rtt in self.rtts_before_loss[1]:
            if rtt > median_rtt_ms * 2.2 and rtt >= 20:
                inflated_rtt_count_on_loss += 1

        return ((float)(inflated_rtt_count_on_loss) / len(self.rtts_before_loss[1]) )


        

class TokenBucketSim(object):

    def __init__(self, TcpPlot):
        self.node_number = 0
        self.nodes = []
        self.policing_rate_bps = 0
        self.first_loss = None
        self.last_loss = None

        self.median_rtt_ms = TcpPlot.get_median_rtt_ms(0)

        if self.median_rtt_ms == -1:
            self.median_rtt_us = -1
        else:
            self.median_rtt_us = self.median_rtt_ms * 1000

        self.init_token_bucket_simulator(TcpPlot)

    # Find the first lost and the last lost packets
    # Append all node-pairs to the result_node list.
    def init_token_bucket_simulator(self, TcpPlot):
        result_nums = 0
        result_nodes = []
        index = 0

        first_loss = last_loss = None

        uncompress_nodes_number = TcpPlot.uncompress_nodes_number
        uncompress_nodes = TcpPlot.uncompress_nodes

        while index < uncompress_nodes_number:
            if index == 0 or index == uncompress_nodes_number - 1:
                result_nodes.append(uncompress_nodes[index])
                result_nums += 1
            elif uncompress_nodes[index].is_lost == True:

                if first_loss == None:
                    first_loss = uncompress_nodes[index]

                result_nodes.append(uncompress_nodes[index])
                result_nums += 1

                if index > 1 and uncompress_nodes[index - 1].is_lost == False:
                    result_nodes.append(uncompress_nodes[index - 1])
                    result_nums += 1

            index += 1

        for node in reversed(uncompress_nodes):
            if node.is_lost:
                if last_loss == None:
                    last_loss = node
                    break
            continue

        self.node_number = result_nums
        self.nodes = result_nodes
        self.policing_rate_bps = TcpPlot.goodput_for_range(first_loss, last_loss, 0)
        self.first_loss = first_loss
        self.last_loss = last_loss


    def token_bucket_simulator(self):

        if self.first_loss == None or self.last_loss == None:
            return RESULT_INSUFFICIENT_LOSS
        if self.first_loss.seq > LATE_LOSS_THRESHOLD:
            return RESULT_LATE_LOSS

        """
            ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.0
            ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75
            ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.1
            ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03
        """
        loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
            self.median_rtt_us * self.policing_rate_bps / 8E6

        pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
            self.median_rtt_us * self.policing_rate_bps / 8E6

        y_intercept = self.first_loss.seq - (self.first_loss.timestamp_us - self.nodes[0].timestamp_us) \
            * self.policing_rate_bps / 8E6

        # Result code 3: Negative Fill
        if y_intercept < -pass_zero_threshold:
            return RESULT_NEGATIVE_FILL
        
        tokens_available = 0
        tokens_used = 0
        tokens_on_loss = []
        tokens_on_pass = []

        for node in self.nodes:
            tokens_produced = (node.timestamp_us - self.first_loss.timestamp_us) * \
                self.policing_rate_bps / 8E6

            tokens_used = node.bytes_passed
            tokens_available = tokens_produced - tokens_used

            if node.is_lost:
                tokens_on_loss.append(tokens_available)
            else:
                tokens_on_pass.append(tokens_available)

        # Result code 1: Insufficient loss
        if len(tokens_on_loss) < MIN_NUM_SAMPLES or len(tokens_on_pass) < MIN_NUM_SAMPLES:
            return RESULT_INSUFFICIENT_LOSS

        # Result code 4: Higher Fill on Loss
        if mean(tokens_on_pass) <= mean(tokens_on_loss) or \
            median(tokens_on_pass) <= median(tokens_on_loss):
            return RESULT_HIGHER_FILL_ON_LOSS

        """
            Result code 5: Loss Fill Out of Range
            Token bucket is roughly empty when experiencing loss.
            Result code 6: Pass Fill Out of Range
            Token bucket cannot be empty when experiencing pass.
        """
        median_tokens_on_loss = median(tokens_on_loss)
        out_of_range = 0
        for token in tokens_on_loss:
            if abs(token - median_tokens_on_loss) > loss_zero_threshold:
                out_of_range += 1
        if out_of_range > len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE:
            return RESULT_LOSS_FILL_OUT_OF_RANGE

        median_tokens_on_pass = median(tokens_on_pass)
        out_of_range = 0
        for token in tokens_on_pass:
            if abs(token - median_tokens_on_pass) > pass_zero_threshold:
                out_of_range += 1
        if out_of_range > len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE:
            return RESULT_PASS_FILL_OUT_OF_RANGE

        return 0

"""
    The CompressedPacket data structure is generated from several AnnotatedPackets based on
    different approximation approaches, such as the linear least-square approximation.
"""
class TcpPlot(object):

    def __init__(self, endpoint):
        self.ip = endpoint.ip 
        self.port = endpoint.port
        self.time_base = endpoint.packets[0].timestamp_us
        
        """ The data structure saves time-sequence plot """
        self.uncompress_nodes_number = 0
        self.uncompress_nodes = []

        self.compress_nodes_number = []
        self.compress_nodes = []

        """ Compression type: 0 for uncompressed plot, 1 for others """
        self.get_uncompressed_plot(endpoint)
        self.get_compressed_plot()
    
    def get_uncompressed_plot(self, endpoint):
        for packet in endpoint.packets:
            current_node = TcpNode()
            current_node.packet_node_converter(packet, self.time_base)
            self.uncompress_nodes_number += 1
            self.uncompress_nodes.append(current_node)

    def get_compressed_plot(self):
        self.get_compressed_plot_1()
        self.get_compressed_plot_2()

    def get_compressed_plot_1(self):
        """"
        Compression type No. 1:
        When we come across a loss packet, we record the packet.
        When a packet gets through the link, we do not record the packet.
        We use the first pacekt and the last packet to refer to a non-lossy-packet segment.

        This implementation can guarantee a correct throughput, and can reflect every packet 
        that got lost.
        """
        result_nums = 0
        result_nodes = []
        index = 0
        while index < self.uncompress_nodes_number:
            if index == 0 or index == self.uncompress_nodes_number - 1:
                result_nodes.append(self.uncompress_nodes[index])
                result_nums += 1
            elif self.uncompress_nodes[index].is_lost == True:
                result_nodes.append(self.uncompress_nodes[index])
                result_nums += 1
            index += 1
        self.compress_nodes_number.append(result_nums)
        self.compress_nodes.append(result_nodes)

    def get_compressed_plot_2(self):
        result_nums = 0
        result_nodes = []

        result_nodes.append(self.uncompress_nodes[0])
        result_nums += 1
        lost_packet_count = result_nodes[0].is_lost
        prev_state = result_nodes[0].is_lost
        cont_state = 1

        index = 1
        while index < self.uncompress_nodes_number - 1:
            if self.uncompress_nodes[index].is_lost != prev_state:
                result_nodes[-1].cont_state_packet_number = cont_state
                cont_state = 0
                result_nodes.append(self.uncompress_nodes[index])
                result_nums += 1

            prev_state = self.uncompress_nodes[index].is_lost
            cont_state += 1
            index += 1

        if self.uncompress_nodes[index].is_lost != prev_state:
            result_nodes[-1].cont_state_packet_number = cont_state
            result_nodes.append(self.uncompress_nodes[index])
            result_nodes[-1].cont_state_packet_number = 1
        else:
            result_nodes[-1].cont_state_packet_number = cont_state + 1
            result_nodes.append(self.uncompress_nodes[index])
            result_nodes[-1].cont_state_packet_number = 0
        result_nums += 1

        self.compress_nodes_number.append(result_nums)
        self.compress_nodes.append(result_nodes)

    def get_compressed_plot_3(self):
        result_nums = 0
        result_nodes = []

        index = 1
        previous_node = None
        current_node = self.uncompress_nodes[0]
        while index < self.uncompress_nodes_number - 1:
            previous_node = current_node
            current_node = self.uncompress_nodes[index]

            if previous_node.is_lost == False and current_node.is_lost == True:
                loss_count = 1
                index += 1
                while self.uncompress_nodes[index].is_lost == True:
                    loss_count += 1
                    index += 1
                current_node.accumulative_lost_packet_count = loss_count
                
                result_nums += 2
                result_nodes.append([previous_node, current_node])

                current_node = self.uncompress_nodes[index]
                continue

            index += 1

        self.compress_nodes_number.append(result_nums)
        self.compress_nodes.append(result_nodes)

    def get_losses_number(self, compression_type):
        if compression_type == 0:
            return self.get_losses_number_0()
        elif compression_type == 1:
            return self.get_losses_number_1()
        elif compression_type == 2:
            return self.get_losses_number_2()
        else:
            return 0

    def get_losses_number_0(self):
        nums = 0
        for index in range(self.uncompress_nodes_number):
            if self.uncompress_nodes[index].is_lost == True:
                nums += 1
        return nums

    def get_losses_number_1(self):
        length = self.compress_nodes_number[0]
        nums = length - 2 + \
        self.compress_nodes[0][0].is_lost + self.compress_nodes[0][length - 1].is_lost
        return nums

    def get_losses_number_2(self):
        length = self.compress_nodes_number[1]
        nums = 0
        for index in range(length - 1):
            if self.compress_nodes[1][index].is_lost:
                nums += self.compress_nodes[1][index].cont_state_packet_number
        return nums

    def get_median_rtt_ms(self, compression_type):
        return self.get_median_rtt_ms_0()

    def get_median_rtt_ms_0(self):
        rtts = []
        for node in self.uncompress_nodes:
            if node.rtx == None and node.rtt_ms != -1:
                rtts.append(node.rtt_ms)
        if len(rtts) >= 1:
            median_rtt_ms = median(rtts)
        else:
            median_rtt_ms = -1
        return median_rtt_ms

    """ Compute the goodput (in bps) achieved between observing two specific packets """
    def goodput_for_range(self, first_node, second_node, compression_type):
        if compression_type == 0:
            return self.goodput_for_range_0(first_node, second_node)
        elif compression_type == 1:
            return self.goodput_for_range_1(first_node, second_node)
        elif compression_type == 2:
            return self.goodput_for_range_2()
        else:
            return 0

    def goodput_for_range_0(self, first_node, second_node):
        if first_node == second_node or first_node.timestamp_us >= second_node.timestamp_us:
            return 0

        byte_count = 0
        seen_first = False
        for node in self.uncompress_nodes:
            if node == second_node:
                break
            if node == first_node:
                seen_first = True
            if not seen_first:
                continue

            if not node.is_lost:
                byte_count += node.data_len

        # print first_node.timestamp_us, second_node.timestamp_us, byte_count

        time_slice_us = second_node.timestamp_us - first_node.timestamp_us
        return byte_count * 8E6 / time_slice_us

    def goodput_for_range_1(self, first_node, second_node):
        if first_node == second_node or first_node.timestamp_us >= second_node.timestamp_us:
            return 0

        time_slice_us = second_node.timestamp_us - first_node.timestamp_us
        byte_count = second_node.bytes_passed - first_node.bytes_passed
        return byte_count * 8 * 1E6 / time_slice_us

    def goodput_for_range_2(self):
        left_edge = first_node
        right_edge = self.compress_nodes[1][self.compress_nodes_number[1] - 2]

        time_slice_us = right_edge.timestamp_us - left_edge.timestamp_us
        byte_count = right_edge.bytes_passed - left_edge.bytes_passed
        return byte_count * 8 * 1E6 / time_slice_us

    def policing_rate_bps(self):
        uncompress_nodes = self.uncompress_nodes
        uncompress_nodes_number = self.uncompress_nodes_number

        first_loss = last_loss = None
        for node in uncompress_nodes:
            if node.is_lost:
                first_loss = node
                break

        for node in reversed(uncompress_nodes):
            if node.is_lost:
                last_loss = node
                break

        if first_loss == last_loss:
            return 0

        #print first_loss.bytes_passed, last_loss.bytes_passed
        #print first_loss.timestamp_us, last_loss.timestamp_us

        return self.goodput_for_range_0(first_loss, last_loss)




def get_policing_params_from_plot_0(ts_plot, cutoff = 0):
    # 1. Find the first loss and the last loss
    uncompress_nodes = ts_plot.uncompress_nodes
    uncompress_nodes_numer = ts_plot.uncompress_nodes_number

    first_loss = last_loss = first_loss_no_skip = None
    skipped = 0
    for node in uncompress_nodes:
        if node.is_lost:
            if first_loss_no_skip is None:
                first_loss_no_skip = node
            if cutoff == skipped:
                first_loss = node
                break
            else:
                skipped += 1
    if first_loss == None:
        print "Insufficient Loss -- CODE 1-1"
        return RESULT_INSUFFICIENT_LOSS

    skipped = 0
    for node in reversed(uncompress_nodes):
        if node.is_lost:
            if node == first_loss:
                break
            if cutoff == skipped:
                last_loss = node
                break
            else:
                skipped += 1
    if last_loss == None:
        print "Insufficient Loss -- CODE 1-2"
        return RESULT_INSUFFICIENT_LOSS

    if first_loss.seq > LATE_LOSS_THRESHOLD:
        print "Result Late Loss -- CODE 2-1"
        return RESULT_LATE_LOSS

    policing_rate_bps = ts_plot.goodput_for_range(first_loss, last_loss, 0)
    # print policing_rate_bps

    median_rtt_us = ts_plot.get_median_rtt_ms(0) * 1000
    """
        ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.0 
        ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75
    """
    loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6

    pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6
    
    y_intercept = first_loss.seq - first_loss.timestamp_us * policing_rate_bps / 8E6
    
    #print "y_intercept:", y_intercept


    if y_intercept < -pass_zero_threshold:
        #print "Result Negative Fill"
        return RESULT_NEGATIVE_FILL

    """
        Iterate through all the nodes in time-sequence plot.
        We simulate a policer starting with an empty token bucket.
        Tokens are inserted at the policing rate (policing_rate_bps / 8E6).
    """
    tokens_available = 0
    tokens_used = 0
    tokens_on_loss = []
    tokens_on_pass = []

    times_on_loss = []
    times_on_pass = []

    seen_first = seen_first_no_skip = False
    burst_size = 0
    inflated_rtt_count = 0
    all_rtt_count = 0
    rtts = []

    slices_with_loss = 1
    slice_end = first_loss.timestamp_us + median_rtt_us

    ignore_index = -1
    tokens_on_loss_out_of_range = 0

    for node in uncompress_nodes:
        if node.rtx != None:
            ignore_index = max(ignore_index, node.ack_index)

        if node.rtx == None and node.rtt_ms != -1 and node.index > ignore_index:
            rtts.append(node.rtt_ms)

        if node == first_loss:
            seen_first = True
        if node == first_loss_no_skip:
            seen_first_no_skip = True
        if not seen_first_no_skip:
            burst_size += node.data_len
        if not seen_first:
            continue

        tokens_produced = (node.timestamp_us - first_loss.timestamp_us) * \
            policing_rate_bps / 8E6
        tokens_available = tokens_produced - tokens_used

        #print node.is_lost, node.bytes_passed, tokens_produced, tokens_used, tokens_available

        if node.is_lost:
            tokens_on_loss.append(tokens_available)
            times_on_loss.append(node.timestamp_us)

            if len(rtts) > 1 and rtts[-2] >= percentile(rtts, 50) \
                and rtts[-2] > INFLATED_RTT_THRESHOLD * percentile(rtts, INFLATED_RTT_PERCENTILE) \
                and rtts[-2] >= 20:
                inflated_rtt_count += 1

            all_rtt_count += 1

            if node.timestamp_us > slice_end:
                slice_end = node.timestamp_us + median_rtt_us
                slices_with_loss += 1

        else:
            tokens_on_pass.append(tokens_available)
            times_on_pass.append(node.timestamp_us)
            tokens_used += node.data_len

    # Debug information: for the token bucket simulator debug
    #print tokens_on_pass, tokens_on_loss
    print tokens_on_pass
    print

    # MIN_NUM_SLICES_WITH_LOSS = 3
    if slices_with_loss < MIN_NUM_SLICES_WITH_LOSS:
        print "Insufficient Loss -- CODE 1-3 (Slice)"
        return RESULT_INSUFFICIENT_LOSS

    # MIN_NUM_SAMPLES = 15
    if len(tokens_on_pass) < MIN_NUM_SAMPLES or len(tokens_on_loss) < MIN_NUM_SAMPLES:
        print "Insufficient Loss -- CODE 1-4"
        return RESULT_INSUFFICIENT_LOSS


    """
        a. There should be more tokens available when packets pass through
        compared to loss
    """
    #print "Tobi's Algorithm"
    #print tokens_on_pass, times_on_pass
    #print tokens_on_loss, times_on_loss

    if mean(tokens_on_pass) <= mean(tokens_on_loss) or \
        median(tokens_on_pass) <= median(tokens_on_loss):
        #print "Result Higher Fill on Loss"
        return RESULT_HIGHER_FILL_ON_LOSS

    """
        b. Token bucket is (roughly) empty when experiencing loss
        To account for possible imprecisions regrading the timestamps when            
        the token bucket was empty, we subtract the median fill level on loss
        from all token count samples.
    """
    median_tokens_on_loss = median(tokens_on_loss)
    out_of_range = 0
    for tokens in tokens_on_loss:
        if abs(tokens - median_tokens_on_loss) > loss_zero_threshold:
            out_of_range += 1
    if len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE < out_of_range:
        #print "Result Loss Fill Out of Range"
        return RESULT_LOSS_FILL_OUT_OF_RANGE

    """
        c. Token bucket is NOT empty when packets go through
        To account for possible imprecision regarding the timestamps when
        the token bucket was empty, we subtract the median fill level on loss
        from all token count samples.
        (median fill level on loss ~= an empty bucket)
    """
    out_of_range = 0
    for tokens in tokens_on_pass:
        if tokens - median_tokens_on_loss < -pass_zero_threshold:
            out_of_range += 1
    if len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE < out_of_range:
        #print "Result Pass Fill Out of Range"
        return RESULT_PASS_FILL_OUT_OF_RANGE

    """
        d. RTT should not inflate before loss events (rtt[-2])
        all_rtt_count = count when the packet is lost
        inflated_rtt_count = inflated RTT count when the packet is lost
    """
    rtt_threshold = INFLATED_RTT_TOLERANCE * all_rtt_count
    if inflated_rtt_count > rtt_threshold:
        #print "Result Inflated RTT"
        return RESULT_INFLATED_RTT

    #return "Policing is detected in this flow"
    return RESULT_OK

def get_policing_params_from_plot_1(ts_plot, cutoff = 0):
    # 1. Find the first loss and the last loss
    compress_nodes = ts_plot.compress_nodes[0]
    compress_nodes_number = ts_plot.compress_nodes_number

    first_loss = last_loss = first_loss_no_skip = None
    skipped = 0
    for node in compress_nodes:
        if node.is_lost:
            if first_loss_no_skip == None:
                first_loss_no_skip = node
            if cutoff == skipped:
                first_loss = node
            else:
                skipped += 1
    if first_loss == None:
        print "Insufficient Loss"
        return 0

    skipped = 0
    for node in reversed(uncompress_nodes):
        if node.is_lost:
            if node == first_loss:
                break
            if cutoff == skipped:
                last_loss = node
                break
            else:
                skipped += 1
                continue
    if last_loss == None:
        print "Insufficient Loss"
        return 0

    if first_loss.seq > LATE_LOSS_THRESHOLD:
        print "Result Late Loss"
        return 0

    policing_rate_bps = ts_plot.goodput_for_range(first_loss, last_loss, 1)
    median_rtt_us = ts_plot.get_median_rtt_ms(0) * 1000

    """
        ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.0 
        ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75
    """
    loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6
    pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6

    y_intercept = first_loss.seq - ((first_loss.timestamp_us - compress_nodes[0].timestamp_us) * \
        policing_rate_bps / 8E6)

    if y_intercept < -pass_zero_threshold:
        print "Result Negative Fill"
        return 0

    """
        Iterate through all the nodes in time-sequence plot.
        We simulate a policer starting with an empty token bucket.
        Tokens are inserted at the policing rate (policing_rate_bps / 8E6).
    """
    tokens_available = 0
    tokens_used = 0
    tokens_on_loss = []
    tokens_on_pass = []

    seen_first = seen_first_no_skip = False
    burst_size = 0
    inflated_rtt_count = 0
    all_rtt_count = 0
    rtts = []

    slices_with_loss = -1
    slice_end = first_loss.timestamp_us + median_rtt_us

    ignore_index = -1
    tokens_on_loss_out_of_range = 0

    for node in compress_nodes:

        if node == first_loss:
            seen_first = True
        if node == first_loss_no_skip:
            seen_first_no_skip = True
        if not seen_first_no_skip:
            burst_size = node.bytes_passed
        if not seen_first:
            continue

        tokens_produced = (node.timestamp_us - first_loss.timestamp_us) * \
            policing_rate_bps / 8E6
        tokens_available = tokens_produced - tokens_used

        """
            After the first loss, all nodes which were recored in the compressed plot 1
            are lost.
        """
        tokens_on_loss.append(tokens_available)

        if node.timestamp_us > slice_end:
            slice_end = node.timestamp_us + median_rtt_us
            slices_with_loss += 1





















