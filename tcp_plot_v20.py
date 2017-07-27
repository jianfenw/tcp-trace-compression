from matplotlib.pylab import gca, figure, axes, plot, scatter, subplot, title, xlabel, ylabel, xlim, ylim, show
from matplotlib.lines import Line2D
import numpy as np
from numpy import arange, array, ones
from numpy.linalg import lstsq

import dpkt
from tcp_endpoint import *
from tcp_flow import *
from tcp_util import *
from tcp_plot import *
from tcp_compress_plot import *

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
# Currently, 0.40 / 0.53
# Originally, 0.10 / 0.03
ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.10
ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03

# based on loss_number() and pass_number()
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

# The implementation based on approximation method

class TcpComPlotV30(object):

    def __init__(self, TcpPlot, MaxError=0):

        self.uncompress_nodes_number = TcpPlot.uncompress_nodes_number
        uncompress_nodes = TcpPlot.uncompress_nodes

        '''
        # Debug info: for the algorithm implementation
        loss_sum = 0
        for node in uncompress_nodes:
            if node.is_lost:
                loss_sum += 1
        print loss_sum
        '''

        self.first_node = uncompress_nodes[0]
        self.end_node = uncompress_nodes[self.uncompress_nodes_number - 1]

        self.node_segment = []
        self.node_segment_number = 0

        self.first_node_loss = (self.first_node).is_lost

        self.loss_segment = []
        self.pass_segment = []

        self.loss_count = -1

        self.compression_ratio = -1

        self.policing_rate_bps = -1

        # The median value of RTT time for this flow (all nodes)
        self.median_rtt_ms = -1

        # Flag for policing detection
        self.late_loss_flag = -1
        self.inflated_rtt_flag = -1
        self.token_bucket_flag = -1

        self.tokens_on_pass_range = -1
        self.tokens_on_loss_range = -1
        self.tokens_on_pass_total_range = -1
        self.tokens_on_loss_total_range = -1

        self.token_number_on_pass = -1
        self.token_number_on_loss = -1

        # Set the median value of RTT time
        tmp_rtts = []
        for i in range(self.uncompress_nodes_number):
            if uncompress_nodes[i].rtx is None and uncompress_nodes[i].rtt_ms != -1:
                tmp_rtts.append(uncompress_nodes[i].rtt_ms)
        if len(tmp_rtts) >= 1:
            self.median_rtt_ms = median(tmp_rtts)

        """
            Here is the compression procedure, in which we want to record the first and 
            the last packets for each loss event and a series of pass packets.

            Init Process:
            Decide whether the first few packets are lost packets or successfully
            transmitted packets.

            General Process:
            We try to record every packet segment for the flow.

            A packet segment contains the first packet, the last packet, and also 
            the total number of packets for the segment.

            For a sequence of successfully transmitted packets, we still have to 
            record more details, such as recording each window.

            loss_segment: [segment_first_node_index, segment_last_node_index, loss_count]
            pass_segment: [[sub_seg_list...], pass_count]
                [sub_seg_list] = [nodes that are recored in the compressed plot]
        """

        segment_first_node_index = None
        segment_last_node_index = None

        loss_count = 0
        pass_count = 0
        index = 0
        count = 0
        last_segment_pass = self.first_node_loss
        MAX_INTER_P_PACKET_NUM = 1
        MAX_ERROR = MaxError

        while index <= self.uncompress_nodes_number - 1:
            if last_segment_pass:
                # Current segment is a loss segment
                segment_first_node_index = index

                index += 1
                loss_count = 1
                count = 0

                for j in range(index, self.uncompress_nodes_number):
                    if uncompress_nodes[j].is_lost:
                        loss_count += 1
                        count = 0
                    else:
                        count += 1
                        if count >= MAX_INTER_P_PACKET_NUM:
                            break
                index = j

                if index - segment_first_node_index >= MAX_INTER_P_PACKET_NUM:
                    segment_last_node_index = index - MAX_INTER_P_PACKET_NUM
                else:
                    # When MAX_INTER_P_PACKET_NUM >= 2
                    segment_last_node_index = segment_first_node_index
                    index += 1

                self.node_segment.append([ uncompress_nodes[segment_first_node_index], \
                    uncompress_nodes[segment_last_node_index], loss_count])
                self.node_segment_number += 1
                index = index - MAX_INTER_P_PACKET_NUM + 1
                last_segment_pass = False

            else:
                # Current segment is a pass segment
                segment_first_node_index = index

                current_segment = []
                current_segment.append(uncompress_nodes[segment_first_node_index])

                index += 1
                pass_count = 1

                if index <= self.uncompress_nodes_number - 1:
                    for j in range(index, self.uncompress_nodes_number):
                        if not uncompress_nodes[j].is_lost:
                            current_segment.append(uncompress_nodes[j])
                            pass_count += 1
                        else:
                            break
                    index = j

                    if index == self.uncompress_nodes_number - 1:
                        segment_last_node_index = index
                        index += 1
                    else:
                        segment_last_node_index = index - 1
                else:
                    segment_last_node_index = segment_first_node_index

                result_nodes = get_compressed_plot(current_segment, interpolate, \
                    sumsquared_error, MAX_ERROR)

                self.node_segment.append([result_nodes, pass_count])
                self.node_segment_number += 1
                last_segment_pass = True

        loss_segment_flag = self.first_node_loss
        node_count = 0
        for i in range(self.node_segment_number):
            if loss_segment_flag:
                self.loss_segment.append(self.node_segment[i])
                node_count += 2
                if self.node_segment[i][2] == 1:
                    node_count -= 1
                loss_segment_flag = False
            else:
                self.pass_segment.append(self.node_segment[i])
                node_count += len(self.node_segment[i][0])
                if self.node_segment[i][1] == 1:
                    node_count -= 1
                loss_segment_flag = True

        self.compression_ratio = float(node_count) / float(self.uncompress_nodes_number)

    def implementation_validation(self):

        # Check the sum of pass_count
        # For each segment of successfully transmitted packets,
        # sum_pass = the total # of packets in all sub-segments

        sum_pass = 0
        for i in range(len(self.pass_segment)):
            sum_pass = 0
            pass_node_list = self.pass_segment[i][0]
            pass_count = self.pass_segment[i][1]
            #total_pass_count += pass_count

            '''
            # Debug info: debug the number of pass_count

            if i == 0:
                print pass_node_list
            '''

            for j in range(len(pass_node_list)):
                sum_pass += pass_node_list[j][1]

            if sum_pass != pass_count + len(pass_node_list) - 2:
                print sum_pass, pass_count, len(pass_node_list)
                return "Implementation Error: Code 1"

        single_loss_count = 0

        for i in range(len(self.loss_segment)):
            if self.loss_segment[i][2] == 1:
                single_loss_count += 1
        print single_loss_count, len(self.loss_segment), len(self.pass_segment)

        single_pass_count = 0

        for i in range(len(self.pass_segment)):
            current_segment = self.pass_segment[i][0]
            current_segment_packet_num = self.pass_segment[i][1]

            for segment in current_segment:
                print len(segment), segment[1], current_segment_packet_num, len(current_segment)





        """
        loss_segment_flag = self.first_node_loss
        one_loss_segment_count = 0
        one_pass_segment_count = 0
        pass_count = 0
        for i in range(self.node_segment_number):
            if loss_segment_flag:
                print self.node_segment[i][2]
                if self.node_segment[i][2] == 1:
                    one_loss_segment_count += 1
                loss_segment_flag = False
            else:
                #print len(self.node_segment[i][0]), (self.node_segment[i][1])
                if self.node_segment[i][1] == 1:
                    one_pass_segment_count += 1
                pass_count += len(self.node_segment[i][0])
                loss_segment_flag = True
                continue
        print one_loss_segment_count, one_pass_segment_count, len(self.loss_segment), pass_count
        """
        return "No Error"

    def loss_number(self):
        """
            Return: the number of losses in the flow
        """
        if self.loss_count != -1:
            return self.loss_count

        loss_count = 0
        if self.first_node_loss:
            offset = 0
        else:
            offset = 1

        for i in range(self.node_segment_number):
            if (i+offset) % 2 == 0:
                loss_count += self.node_segment[i][2]

        self.loss_count = loss_count
        return self.loss_count


    def pass_number(self):

        return (self.uncompress_nodes_number - self.loss_number())

    def avg_goodput(self):
        if len(self.loss_segment) == 0:
            return -1

        first_node = self.loss_segment[0][0]
        second_node = self.loss_segment[len(self.loss_segment) - 1][1]

        time_us = second_node.timestamp_us - first_node.timestamp_us
        bytes_count = second_node.bytes_passed - first_node.bytes_passed

        return bytes_count * 8 * 1E6 / time_us

    def set_late_loss_flag(self):
        if self.late_loss_flag != -1:
            return self.late_loss_flag

        if len(self.loss_segment) == 0:
            self.late_loss_flag = -1
            return

        first_loss = self.loss_segment[0][0]

        # LATE_LOSS_THRESHOLD = 2E6
        if first_loss.seq > LATE_LOSS_THRESHOLD:
            self.late_loss_flag = 1
        else:
            self.late_loss_flag = 0
        return

    def set_inflated_rtt_flag(self):
        if self.inflated_rtt_flag != -1:
            return self.inflated_rtt_flag

        if len(self.loss_segment) == 0:
            self.inflated_rtt_flag = -1
            return

        rtt_count = 0
        inflated_rtt_count = 0

        if self.first_node_loss:
            offset = 0
        else:
            offset = 1

        for i in range(offset, self.node_segment_number):
            if (i+offset) % 2 == 0:
                # The current segment is a loss segment
                if i == 0:
                    continue
                else:
                    #f_node = self.node_segment[i][0]
                    #e_node = self.node_segment[i][1]
                    #packet_num = self.node_segment[i][2]

                    last_segment = self.node_segment[i-1][0]
                    last_segment_packet_num = self.node_segment[i-1][1]
                    target_packet = last_segment[len(last_segment)-1][0]

                    rtt_count += 1
                    if target_packet.rtt_ms >= self.median_rtt_ms * 2.2 and \
                        target_packet.rtt_ms >= 20:
                        inflated_rtt_count += 1

        rtt_threshold = 0.85 * rtt_count
        
        if inflated_rtt_count > rtt_threshold:
            self.inflated_rtt_flag = 1
        else:
            self.inflated_rtt_flag = 0

        return

    def set_token_bucket_flag(self):
        if self.token_bucket_flag != -1:
            return self.token_bucket_flag

        # Case 1: No lost packet is available
        if len(self.loss_segment) == 0:
            self.token_bucket_flag = -1
            return

        # Get the traffic policing rate (measured in bps)
        self.policing_rate_bps = self.avg_goodput()
        #print "POLICING RATE (BPS):", self.policing_rate_bps

        first_loss = self.loss_segment[0][0]
        """
            ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.0
            ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75
            ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.1 / 0.2
            ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03
        """
        loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
            self.median_rtt_ms * 1000 * self.policing_rate_bps / 8E6
        pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
            self.median_rtt_ms * 1000 * self.policing_rate_bps / 8E6

        #print loss_zero_threshold, pass_zero_threshold, self.median_rtt_ms

        # Case 2:
        # The idea is that the number of tokens in the token bucket cannot be negative
        # If the NEGATIVE_FILL happends, we can conclude that the token bucket mode
        # does not hold.
        y_intercept = first_loss.seq - \
            (first_loss.timestamp_us - self.first_node.timestamp_us) * \
            self.policing_rate_bps / 8E6

        if y_intercept < -pass_zero_threshold:
            self.token_bucket_flag = RESULT_NEGATIVE_FILL
            return

        tokens_available = 0
        tokens_used = 0
        tokens_on_pass = []
        tokens_on_loss = []

        # Here is the main token bucket procedure:
        # Notes: tokens_on_loss must have 0 token at the first loss and the last loss

        if self.first_node_loss:
            offset = 0
        else:
            offset = 1

        for i in range(offset, self.node_segment_number):

            if (i+offset) % 2 == 0:
                # The current segment is a loss segment
                f_node = self.node_segment[i][0]
                e_node = self.node_segment[i][1]
                packet_num = self.node_segment[i][2]

                segment_packets = segment_recovery(True, f_node, e_node, packet_num)

                for target_packet in segment_packets:
                    tokens_produced = (target_packet.timestamp_us - first_loss.timestamp_us) * \
                        self.policing_rate_bps / 8E6
                    tokens_used = target_packet.bytes_passed - first_loss.bytes_passed
                    tokens_available = tokens_produced - tokens_used

                    tokens_on_loss.append(tokens_available)

            else:
                # The current segment is a pass segment
                # (We have to deal with each sub-segment)
                # There are segments which have only one packet in it.

                current_segment = self.node_segment[i][0]
                current_packet_num = self.node_segment[i][1]

                # Look at the first packet
                target_packet = current_segment[0][0]

                tokens_produced = (target_packet.timestamp_us - first_loss.timestamp_us) * \
                    self.policing_rate_bps / 8E6
                tokens_used = target_packet.bytes_passed - first_loss.bytes_passed
                tokens_available = tokens_produced - tokens_used

                tokens_on_pass.append(tokens_available)

                # Look at each sub-segment
                # We have to skip the first packet in each sub-segment!
                for index in range(1, len(current_segment)):

                    f_node = current_segment[index-1][0]
                    e_node = current_segment[index][0]
                    packet_num = current_segment[index][1]
                    
                    segment_packets = segment_recovery(False, f_node, e_node, packet_num)
                    
                    flag = False
                    if index != 0:
                        flag = True
                    
                    for target_packet in segment_packets:
                        
                        if flag:
                            flag = False
                            continue
                        
                        tokens_produced = (target_packet.timestamp_us - first_loss.timestamp_us) * \
                            self.policing_rate_bps / 8E6
                        tokens_used = target_packet.bytes_passed - first_loss.bytes_passed
                        tokens_available = tokens_produced - tokens_used

                        tokens_on_pass.append(tokens_available)
                '''
                # Debug info: debug the case in which (len(tokens_on_pass) != pass_count)
                #print current_packet_num, len(tokens_on_pass) - current_length
                '''

        #print "MEAN:", mean(tokens_on_pass), mean(tokens_on_loss), "MEDIAN:", median(tokens_on_pass), median(tokens_on_loss)
        #print len(tokens_on_pass), len(tokens_on_loss)
        
        # Case 3: tokens_on_pass must be greater than tokens_on_loss

        #print mean(tokens_on_pass), mean(tokens_on_loss)
        #print median(tokens_on_pass), median(tokens_on_loss)
        #print tokens_on_loss

        if mean(tokens_on_pass) <= mean(tokens_on_loss) or \
            median(tokens_on_pass) <= median(tokens_on_loss):
            self.token_bucket_flag = RESULT_HIGHER_FILL_ON_LOSS
            return

        # Case 4: Token bucket is empty when experiencing loss, i.e.
        # packets are dropped due to a lack of tokens.
        # To account for possible imprecisions regarding the timestamps when the token bucket
        # was empty, we subtract the median fill level on loss from all token count samples.

        median_tokens_on_loss = median(tokens_on_loss)
        out_of_range = 0
        for token in tokens_on_loss:
            if abs(token - median_tokens_on_loss) > loss_zero_threshold:
                out_of_range += 1

        self.tokens_on_loss_range = float(out_of_range) / float(len(tokens_on_loss))
        #print len(tokens_on_loss), self.loss_number(), self.tokens_on_loss_range
        #print tokens_on_loss

        #if out_of_range > len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_TOTAL_RANGE:
        if out_of_range > len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE:
            self.token_bucket_flag = RESULT_LOSS_FILL_OUT_OF_RANGE
            return

        # Case 5: Token bucket is NOT empty when packets go through, i.e.
        # the number of estimated tokens in the bucket should not be overly negative
        # To account for possible imprecisions regarding the timestamps when the token bucket
        # was empty, we subtract the median fill level on loss from all token count samples.
        out_of_range = 0
        for token in tokens_on_pass:
            if token - median_tokens_on_loss < -pass_zero_threshold:
                out_of_range += 1

        self.tokens_on_pass_range = float(out_of_range) / float(len(tokens_on_pass))

        if out_of_range > len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE:
            self.token_bucket_flag = RESULT_PASS_FILL_OUT_OF_RANGE
            return

        self.token_bucket_flag = 0
        return

    def check_policing_detector(self):
        self.set_late_loss_flag()
        self.set_token_bucket_flag()
        self.set_inflated_rtt_flag()

    def policing_detector(self):

        # RESULT_INSUFFICIENT_LOSS (1)
        if self.loss_number() < MIN_NUM_SAMPLES or self.pass_number() < MIN_NUM_SAMPLES:
            return 1

        # RESULT_LATE_LOSS (2)
        self.set_late_loss_flag()
        if self.late_loss_flag == 1:
            return 2

        # RESULT_NEGATIVE_FILL (3)
        # RESULT_HIGHER_FILL_ON_LOSS (4)
        # RESULT_LOSS_FILL_OUT_OF_RANGE (5)
        # RESULT_PASS_FILL_OUT_OF_RANGE (6)
        self.set_token_bucket_flag()
        if self.token_bucket_flag >= 1:
            return self.token_bucket_flag

        # RESULT_INFLATED_RTT (7)
        self.set_inflated_rtt_flag()
        if self.inflated_rtt_flag == 1:
            return 7

        # RESULT OK (0)
        return 0

class TcpComPlotV20(object):

    def __init__(self, TcpPlot):

        self.uncompress_nodes_number = TcpPlot.uncompress_nodes_number
        uncompress_nodes = TcpPlot.uncompress_nodes

        '''
        # Debug info: for the algorithm implementation
        loss_sum = 0
        for node in uncompress_nodes:
            if node.is_lost:
                loss_sum += 1
        print loss_sum
        '''

        self.first_node = uncompress_nodes[0]
        self.end_node = uncompress_nodes[self.uncompress_nodes_number - 1]

        self.node_segment = []
        self.node_segment_number = 0
        self.first_node_loss = (self.first_node).is_lost

        self.loss_segment = []
        self.pass_segment = []

        self.loss_count = -1

        self.compression_ratio = -1

        self.policing_rate_bps = -1

        # The median value of RTT time for this flow (all nodes)
        self.median_rtt_ms = -1

        # Flag for policing detection
        self.late_loss_flag = -1
        self.inflated_rtt_flag = -1
        self.token_bucket_flag = -1

        self.tokens_on_pass_range = -1
        self.tokens_on_loss_range = -1
        self.tokens_on_pass_total_range = -1
        self.tokens_on_loss_total_range = -1

        self.token_number_on_pass = -1
        self.token_number_on_loss = -1

        # Set the median value of RTT time
        tmp_rtts = []
        for i in range(self.uncompress_nodes_number):
            if uncompress_nodes[i].rtx is None and uncompress_nodes[i].rtt_ms != -1:
                tmp_rtts.append(uncompress_nodes[i].rtt_ms)
        if len(tmp_rtts) >= 1:
            self.median_rtt_ms = median(tmp_rtts)

        """
            Here is the compression procedure, in which we want to record the first and 
            the last packets for each loss event and a series of pass packets.

            Init Process:
            The first few packets in the flow segment can be lost.
            We add them to the node-pair list and skip this part.

            General Process:
            We try to record every packet segment for the flow.
            A packet segment contains the first packet, the last packet, and also 
            the total number of packets for the segment.
        """

        segment_first_node_index = None
        segment_last_node_index = None
        loss_count = 0
        pass_count = 0
        index = 0
        count = 0
        last_segment_pass = self.first_node_loss
        MAX_INTER_P_PACKET_NUM = 1

        while index <= self.uncompress_nodes_number - 1:
            if last_segment_pass:
                # Current segment is a loss segment
                segment_first_node_index = index

                index += 1
                loss_count = 1
                count = 0

                for j in range(index, self.uncompress_nodes_number):
                    if uncompress_nodes[j].is_lost:
                        loss_count += 1
                        count = 0
                        continue
                    else:
                        count += 1
                        if count >= MAX_INTER_P_PACKET_NUM:
                            break
                index = j

                if index - segment_first_node_index >= MAX_INTER_P_PACKET_NUM:
                    segment_last_node_index = index - MAX_INTER_P_PACKET_NUM
                else:
                    # When MAX_INTER_P_PACKET_NUM >= 2, (index = segment_first_node_index + 1) can
                    # be the last pass packet. However, index - MAX_INTER_P_PACKET_NUM does not
                    # equal to the segment_last_node_index
                    segment_last_node_index = segment_first_node_index
                    index += 1

                self.node_segment.append([uncompress_nodes[segment_first_node_index], \
                    uncompress_nodes[segment_last_node_index], loss_count])
                self.node_segment_number += 1
                index = index - MAX_INTER_P_PACKET_NUM + 1
                last_segment_pass = False
            else:
                # Current segment is a pass segment
                segment_first_node_index = index

                index += 1
                pass_count = 1

                if index <= self.uncompress_nodes_number - 1:
                    for j in range(index, self.uncompress_nodes_number):
                        if uncompress_nodes[j].is_lost:
                            break
                        else:
                            pass_count += 1
                            continue
                    index = j

                    if index == self.uncompress_nodes_number - 1:
                        segment_last_node_index = index
                        index += 1
                    else:
                        segment_last_node_index = index - 1
                else:
                    segment_last_node_index = segment_first_node_index

                self.node_segment.append([uncompress_nodes[segment_first_node_index], \
                    uncompress_nodes[segment_last_node_index], pass_count])
                self.node_segment_number += 1
                last_segment_pass = True


        loss_segment_flag = self.first_node_loss
        for i in range(self.node_segment_number):
            if loss_segment_flag:
                self.loss_segment.append(self.node_segment[i])
                loss_segment_flag = False
            else:
                self.pass_segment.append(self.node_segment[i])
                loss_segment_flag = True

        '''
        # Debug info: for the whole implementation
        for sample in self.loss_segment:
            print sample[2]
        '''

        self.compression_ratio = float(self.node_segment_number) / float(self.uncompress_nodes_number)

    def implementation_validation(self):

        loss_segment_number = len(self.loss_segment)
        pass_segment_number = len(self.pass_segment)
        if loss_segment_number + pass_segment_number != self.node_segment_number:
            return "Implementation Error"
        return "No Error"

    def loss_number(self):

        if self.loss_count != -1:
            return self.loss_count

        loss_count = 0

        if self.first_node_loss:
            offset = 0
        else:
            offset = 1

        for i in range(self.node_segment_number):
            if (i + offset) % 2 == 0:
                loss_count += self.node_segment[i][2]

        self.loss_count = loss_count
        return self.loss_count

    def pass_number(self):
        '''
        # Debug info: loss_num + pass_num != self.uncompress_nodes_number
        # (There are some nodes within every loss event)

        pass_count = 0
        if self.first_node_loss:
            offset = 0
        else:
            offset = 1

        for i in range(self.node_segment_number):
            if (i + offset) % 2 == 1:
                pass_count += self.node_segment[i][2]
        return pass_count
        '''
        return (self.uncompress_nodes_number - self.loss_number())

    def avg_goodput(self):
        if len(self.loss_segment) == 0:
            return -1

        first_node = self.loss_segment[0][0]
        second_node = self.loss_segment[len(self.loss_segment)-1][1]

        time_us = second_node.timestamp_us - first_node.timestamp_us
        bytes_count = second_node.bytes_passed - first_node.bytes_passed

        return bytes_count * 8 * 1E6 / time_us

    def set_late_loss_flag(self):
        if len(self.loss_segment) == 0:
            self.late_loss_flag = -1
            return

        first_loss = self.loss_segment[0][0]
        if first_loss.seq > LATE_LOSS_THRESHOLD:
            self.late_loss_flag = 1
        else:
            self.late_loss_flag = 0

    def set_inflated_rtt_flag(self):

        self.inflated_rtt_flag = 0
        return
        

    def set_token_bucket_flag(self):

        # Case 1: No lost packet is available
        # The token bucket simulator cannot be applied
        if len(self.loss_segment) == 0:
            self.token_bucket_flag = -1
            return

        # The traffic policing rate in bps
        self.policing_rate_bps = self.avg_goodput()

        first_loss = self.loss_segment[0][0]
        
        """
            ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.0
            ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75
            ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.1 / 0.2
            ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03
        """
        loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
            self.median_rtt_ms * 1000 * self.policing_rate_bps / 8E6
        pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
            self.median_rtt_ms * 1000 * self.policing_rate_bps / 8E6

        # Case 2:
        # The idea is that the number of tokens in the token bucket cannot be negative.
        # If the NEGATIVE_FILL happends, we can conclude that the token bucket model does not hold.
        y_intercept = first_loss.seq - \
            (first_loss.timestamp_us - self.first_node.timestamp_us) * \
            self.policing_rate_bps / 8E6

        if y_intercept < -pass_zero_threshold:
            self.token_bucket_flag = RESULT_NEGATIVE_FILL
            return


        tokens_available = 0
        tokens_used = 0
        tokens_on_pass = []
        tokens_on_loss = []

        times_on_loss = []
        times_on_pass = []
        sequence_on_loss = []
        sequence_on_pass = []

        bytes_on_loss = []
        bytes_on_pass = []

        # The main token bucket procedure:
        # Notes: tokens_on_loss must have 0 tokens for the first loss and the last loss
        # (It is due to our assumption)

        if self.first_node_loss:
            offset = 0
        else:
            offset = 1

        for i in range(offset, self.node_segment_number):

            f_node = self.node_segment[i][0]
            e_node = self.node_segment[i][1]
            packet_num = self.node_segment[i][2]

            if (i+offset) % 2 == 0:
                # The current segment is a loss segment
                segment_packets = segment_recovery(True, f_node, e_node, packet_num)

                for target_packet in segment_packets:
                    tokens_produced = (target_packet.timestamp_us - first_loss.timestamp_us) * \
                        self.policing_rate_bps / 8E6
                    tokens_used = target_packet.bytes_passed - first_loss.bytes_passed
                    tokens_available = tokens_produced - tokens_used

                    tokens_on_loss.append(tokens_available)
                    times_on_loss.append(target_packet.timestamp_us)
                    sequence_on_loss.append(target_packet.seq)
                    bytes_on_loss.append(tokens_used)

            else:
                # The current segment is a pass segment
                segment_packets = segment_recovery(False, f_node, e_node, packet_num)

                for target_packet in segment_packets:
                    tokens_produced = (target_packet.timestamp_us - first_loss.timestamp_us) * \
                        self.policing_rate_bps / 8E6
                    tokens_used = target_packet.bytes_passed - first_loss.bytes_passed
                    tokens_available = tokens_produced - tokens_used

                    tokens_on_pass.append(tokens_available)
                    times_on_pass.append(target_packet.timestamp_us)
                    sequence_on_pass.append(target_packet.seq)
                    bytes_on_pass.append(tokens_used)

        #print tokens_on_pass, len(tokens_on_pass)
        #print tokens_on_loss, len(tokens_on_loss)
        print times_on_loss
        print sequence_on_loss
        print times_on_pass
        print sequence_on_pass
        print "MEAN:", mean(tokens_on_pass), mean(tokens_on_loss), "MEDIAN:", median(tokens_on_pass), median(tokens_on_loss)
        #print bytes_on_loss, len(bytes_on_loss)
        #print bytes_on_pass, len(bytes_on_pass)

        # Case 3: tokens_on_pass must be greater than tokens_on_loss

        if mean(tokens_on_pass) <= mean(tokens_on_loss) or \
            median(tokens_on_pass) <= median(tokens_on_loss):
            self.token_bucket_flag = RESULT_HIGHER_FILL_ON_LOSS
            return

        median_tokens_on_loss = median(tokens_on_loss)
        out_of_range = 0
        for token in tokens_on_loss:
            if abs(token - median_tokens_on_loss) > loss_zero_threshold:
                out_of_range += 1

        if out_of_range > self.loss_number() * ZERO_THRESHOLD_LOSS_OUT_OF_TOTAL_RANGE:
            self.token_bucket_flag = RESULT_LOSS_FILL_OUT_OF_RANGE
            return


        median_tokens_on_pass = median(tokens_on_pass)
        out_of_range = 0
        for token in tokens_on_pass:
            if abs(token - median_tokens_on_pass) > pass_zero_threshold:
                out_of_range += 1

        if out_of_range > self.pass_number() * ZERO_THRESHOLD_PASS_OUT_OF_TOTAL_RANGE:
            self.token_bucket_flag = RESULT_PASS_FILL_OUT_OF_RANGE
            return

        self.token_bucket_flag = 0
        return

    def check_policing_detector(self):

        self.set_late_loss_flag()
        self.set_token_bucket_flag()
        self.set_inflated_rtt_flag()

    def policing_detector(self):

        if self.loss_number() < MIN_NUM_SAMPLES or self.pass_number() < MIN_NUM_SAMPLES:
            #print self.loss_number(), self.pass_number(), self.uncompress_nodes_number
            return 0

        # RESULT_LATE_LOSS (2)
        self.set_late_loss_flag()
        if self.late_loss_flag == 1:
            return 1

        # RESULT_NEGATIVE_FILL (3)
        # RESULT_HIGHER_FILL_ON_LOSS (4)
        # RESULT_LOSS_FILL_OUT_OF_RANGE (5)
        # RESULT_PASS_FILL_OUT_OF_RANGE (6)
        self.set_token_bucket_flag()
        if self.token_bucket_flag >= 1:
            return 2

        # RESULT_INFLATED_RTT (0)
        self.set_inflated_rtt_flag()
        if self.inflated_rtt_flag == 1:
            return 3

        return 4

class TcpComPlot(object):

    def __init__(self, TcpPlot):

        self.uncompress_nodes_number = TcpPlot.uncompress_nodes_number
        uncompress_nodes = TcpPlot.uncompress_nodes

        self.first_node = uncompress_nodes[0]
        self.end_node = uncompress_nodes[self.uncompress_nodes_number - 1]

        self.node_pair = []
        self.node_pair_number = 0

        self.loss_count = -1

        self.compression_ratio = -1

        self.policing_rate_bps = -1

        # The median value of RTT time for this flow (all nodes)
        self.median_rtt_ms = -1

        self.late_loss_flag = -1
        self.inflated_rtt_flag = -1
        self.token_bucket_flag = -1

        self.tokens_on_pass_range = -1
        self.tokens_on_loss_range = -1
        self.tokens_on_pass_total_range = -1
        self.tokens_on_loss_total_range = -1


        self.token_number_on_pass = -1
        self.token_number_on_loss = -1


        # Set the median value of RTT time
        tmp_rtts = []
        for i in range(self.uncompress_nodes_number):
            if uncompress_nodes[i].rtx is None and uncompress_nodes[i].rtt_ms != -1:
                tmp_rtts.append(uncompress_nodes[i].rtt_ms)
        if len(tmp_rtts) >= 1:
            self.median_rtt_ms = median(tmp_rtts)

        # Init Process:
        # In some edge case, the first several packets in the flow segment can be lost.
        # We have to skip those packets and add them to the node_pair list.
        # A NodePair = [the first pass, the first loss, pass count, loss count]

        #print self.first_node.is_lost, self.end_node.is_lost

        loss_count = 0
        pass_count = 0
        index = 0

        if self.first_node.is_lost == True:
            index += 1
            loss_count = 1

            count = 0
            for j in range(index, self.uncompress_nodes_number):
                if uncompress_nodes[j].is_lost:
                    loss_count += 1
                    count = 0
                    continue
                else:
                    count += 1
                    if count >= 2:
                        break

            self.first_node.accumulative_lost_packet_count = loss_count
            self.node_pair.append([None, self.first_node, pass_count, loss_count])
            self.node_pair_number += 1

            index = j

        last_node = None
        previous_node = uncompress_nodes[index-1]
        current_node = uncompress_nodes[index]
        pass_count = 2

        """
        # The previous version: the loss event with size 0
        while index < self.uncompress_nodes_number - 1:
            index += 1
            previous_node = current_node
            current_node = uncompress_nodes[index]

            if previous_node.is_lost == False and current_node.is_lost == True:
                loss_count = 1
                index += 1
                while uncompress_nodes[index].is_lost == True:
                    loss_count += 1
                    index += 1
                current_node.accumulative_lost_packet_count = loss_count

                self.node_pair.append([previous_node, current_node, loss_count])
                self.node_pair_number += 1

                previous_node = None
                current_node = uncompress_nodes[index]
                continue
        """
        #print index, uncompress_nodes[index].is_lost

        while index < self.uncompress_nodes_number - 2:
            index += 1
            last_node = previous_node
            previous_node = current_node
            current_node = uncompress_nodes[index]

            if previous_node.is_lost == False and current_node.is_lost:
                loss_count = 1

                count = 0
                for j in range(index+1, self.uncompress_nodes_number):
                    if uncompress_nodes[j].is_lost:
                        loss_count += 1
                        count = 0
                        continue
                    else:
                        count += 1
                        if count >= 2:
                            break
                current_node.accumulative_lost_packet_count = loss_count

                self.node_pair.append([last_node, current_node, pass_count, loss_count])
                self.node_pair_number += 1

                index = j
                last_node = None
                previous_node = uncompress_nodes[index-1]
                current_node = uncompress_nodes[index]
                pass_count = 2
                loss_count = 0
                continue
            else:
                pass_count += 1

        self.node_pair.append([self.end_node, None, pass_count+1, 0])
        self.node_pair_number += 1

        # print "Finished"
        self.compression_ratio = float(self.node_pair_number) / float(self.uncompress_nodes_number)


    """
        This function is used to estimate the general RTT time for the flow.
        We calculate it by using the last nodes in every sequence of pass nodes.
    """
    def last_node_median_rtt(self):
        rtts = []
        if self.node_pair_number == 0:
            return []

        if self.node_pair[0][0] != None:
            rtts.append(self.node_pair[0][0].rtt_ms)

        for i in range(1, self.node_pair_number):
            rtts.append(self.node_pair[i][0].rtt_ms)

        return rtts

    """
        This function is used to test the correctness of algorithm implementation.
        Several things to take care of :
        1. The first packet pair: node_pair[0][0] can be None, while node_pair[0][1] must be lost.
        2. For any other node_pair[index], the first packet must be a normal packet while the 
            second packet must be a lost packet.
    """
    def implementation_validation(self):
        """
        # This is used to debug TcpComPlot __init__()
        # loss_count >= 1
        for node_pair in self.node_pair:
            print node_pair[0], node_pair[1], node_pair[3]
        """

        for index in range(self.node_pair_number):
            if index == 0 and self.node_pair[index][0] == None:
                if self.node_pair[index][1].is_lost:
                    continue
                else:
                    return "Implementation Error"

            if index == self.node_pair_number-1 and self.node_pair[index][1] == None:
                if not self.node_pair[index][0].is_lost:
                    continue
                else:
                    return "Implementation Error"

            if self.node_pair[index][0].is_lost == False and \
                self.node_pair[index][1].is_lost and self.node_pair[index][3] >= 1:
                continue
            else:
                return "Implementation Error"

        return "No Error"

    """
        This function is used to compute the total number of lost packets in the flow segment.
        By adding the loss_count number for each packet pair, we return the total losses. 
    """
    def loss_number(self):
        if self.loss_count != -1:
            return self.loss_count

        loss_count = 0
        for index in range(self.node_pair_number):
            loss_count += self.node_pair[index][3]

        self.loss_count = loss_count
        #print loss_count
        return self.loss_count

    """
        This function gives the total number of transmitted packets in the flow segment.
        pass_number = total packet number - loss_number
    """
    def pass_number(self):
        return (self.uncompress_nodes_number - self.loss_number())

    """
        This function gives the average goodput between the first node pair and the last 
        node pair.
        It can be used as a substitute value for the average throughput of the whole flow.

        Note: first_node = first_loss; last_node = last_loss
    """
    def avg_goodput(self):
        if self.node_pair_number < 2:
            return -1

        first_node = self.node_pair[0][1]
        second_node = self.node_pair[self.node_pair_number - 2][1]

        #print first_node.bytes_passed, second_node.bytes_passed
        #print first_node.timestamp_us, second_node.timestamp_us

        time_us = second_node.timestamp_us - first_node.timestamp_us
        bytes_count = second_node.bytes_passed - first_node.bytes_passed

        return bytes_count * 8 * 1E6 / time_us

    def set_late_loss_flag(self):
        if self.node_pair_number == 0:
            self.late_loss_flag = -1
            return

        first_loss = self.node_pair[0][1]
        if first_loss.seq > LATE_LOSS_THRESHOLD:
            self.late_loss_flag = 1
        else:
            self.late_loss_flag = 0

    def set_inflated_rtt_flag(self):
        if self.node_pair_number == 0:
            self.inflated_rtt_flag = -1
            return

        rtt_count = 0
        inflated_rtt_count = 0

        for i in range(self.node_pair_number):
            if self.node_pair[i][0] == None:
                continue
            rtt_count += 1
            if self.node_pair[i][0].rtt_ms >= self.median_rtt_ms * 2.2 and self.node_pair[i][0].rtt_ms >= 20:
                inflated_rtt_count += 1

        rtt_threshold = 0.85 * rtt_count

        if inflated_rtt_count > rtt_threshold:
            self.inflated_rtt_flag = 1
        else:
            self.inflated_rtt_flag = 0
        return

    def set_token_bucket_flag(self):
        # The traffic policing rate in bps

        if self.node_pair_number == 0:
            self.set_token_bucket_flag = -1
            return

        self.policing_rate_bps = self.avg_goodput()

        first_loss = self.node_pair[0][1]
        # Debug information: for y_intercept computation
        #print "Policing rate:", self.policing_rate_bps, first_loss.timestamp_us, first_loss.seq, self.first_node.timestamp_us, self.first_node.seq
        
        # Case 1: No lost packet is available
        # The token bucket simulator cannot be applied
        
        if self.node_pair_number == 0:
            self.token_bucket_flag = -1
            return

        """
            ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.0
            ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75
            ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.1 / 0.2
            ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03
        """
        loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
            self.median_rtt_ms * 1000 * self.policing_rate_bps / 8E6
        pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
            self.median_rtt_ms * 1000 * self.policing_rate_bps / 8E6

        # Debug information: for loss_zero / pass_zero
        #print "Median RTT(us):", self.median_rtt_ms * 1000, loss_zero_threshold, pass_zero_threshold

        y_intercept = self.node_pair[0][1].seq - \
            (self.node_pair[0][1].timestamp_us - self.first_node.timestamp_us) * \
            self.policing_rate_bps / 8E6

        # Case 2: 
        # The idea is that the token bucket can not have negative number of tokens in it.
        # If the NEGATIVE_FILL happends, we can conclude that the token bucket model does not hold.

        if y_intercept < -pass_zero_threshold:
            self.token_bucket_flag = RESULT_NEGATIVE_FILL
            return

        tokens_available = 0
        tokens_used = 0
        tokens_on_loss = []
        tokens_on_pass = []

        times_on_loss = []
        times_on_pass = []

        # Run the token bucket procedure:
        # Notes: tokens_on_loss must have 0 tokens for the first loss and the last loss

        for i in range(self.node_pair_number):
            if i == 0:
                first_loss = self.node_pair[0][1]

                tokens_on_loss.append(0)
                times_on_loss.append(first_loss.timestamp_us)

                continue

            if i == self.node_pair_number - 1:
                last_pass = self.node_pair[self.node_pair_number-1][0]
                tokens_produced = (last_pass.timestamp_us - first_loss.timestamp_us) * \
                    self.policing_rate_bps / 8E6
                tokens_used = last_pass.bytes_passed - first_loss.bytes_passed
                tokens_available = tokens_produced - tokens_used

                tokens_on_pass.append(tokens_available)
                times_on_pass.append(last_pass.timestamp_us)
                continue


            # tokens_on_pass
            target_node = self.node_pair[i][0]
            #print "Pass Packet Info:", target_node.timestamp_us, target_node.rtt_ms, target_node.is_lost, target_node.data_len

            tokens_produced = (target_node.timestamp_us - first_loss.timestamp_us) * \
                self.policing_rate_bps / 8E6

            tokens_used = target_node.bytes_passed - first_loss.bytes_passed
            tokens_available = tokens_produced - tokens_used
            #print "Tokens on pass:", tokens_produced, tokens_used, tokens_available, target_node.data_len
            tokens_on_pass.append(tokens_available)
            times_on_pass.append(target_node.timestamp_us)

            # tokens_on_loss
            target_node = self.node_pair[i][1]

            tokens_produced = (target_node.timestamp_us - first_loss.timestamp_us) * \
                self.policing_rate_bps / 8E6

            tokens_used = target_node.bytes_passed - first_loss.bytes_passed
            tokens_available = tokens_produced - tokens_used
            #print "Tokens on loss:", tokens_produced, tokens_used, tokens_available, target_node.data_len

            tokens_on_loss.append(tokens_available)
            times_on_loss.append(target_node.timestamp_us)

        # Case 3: tokens_on_pass should be great than or equal to tokens_on_loss

        last_node = self.node_pair[self.node_pair_number-1][1]
        #print last_node.timestamp_us, last_node.bytes_passed, first_loss.timestamp_us, first_loss.bytes_passed, self.policing_rate_bps
        #print self.node_pair_number, self.node_pair[self.node_pair_number-1][1].is_lost, len(tokens_on_pass), len(tokens_on_loss)
        

        self.token_number_on_loss = len(tokens_on_loss)
        self.token_number_on_pass = len(tokens_on_pass)
        
        """
        # Debug info: for result code 4 -- RESULT_HIGHER_FILL_ON_LOSS
        print "My code: token bucket"
        print tokens_on_pass, times_on_pass
        print tokens_on_loss, times_on_loss
        """

        if mean(tokens_on_pass) <= mean(tokens_on_loss) or \
            median(tokens_on_pass) <= median(tokens_on_loss):
            self.token_bucket_flag = RESULT_HIGHER_FILL_ON_LOSS
            return

        median_tokens_on_loss = median(tokens_on_loss)
        out_of_range = 0
        for token in tokens_on_loss:
            if abs(token - median_tokens_on_loss) > loss_zero_threshold:
                out_of_range += 1

        self.tokens_on_loss_range = float(out_of_range) / float(len(tokens_on_loss))
        self.tokens_on_loss_total_range = float(out_of_range) / float(self.loss_number())
        #print out_of_range, self.loss_number(), self.tokens_on_loss_total_range

        #print out_of_range, len(tokens_on_loss), len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE

        
        #if out_of_range > len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE:
        if out_of_range > self.loss_number() * ZERO_THRESHOLD_LOSS_OUT_OF_TOTAL_RANGE:
            self.token_bucket_flag = RESULT_LOSS_FILL_OUT_OF_RANGE
            return
        
        median_tokens_on_pass = median(tokens_on_pass)
        out_of_range = 0
        for token in tokens_on_pass:
            if abs(token - median_tokens_on_pass) > pass_zero_threshold:
                out_of_range += 1

        self.tokens_on_pass_range = float(out_of_range) / float(len(tokens_on_pass))
        self.tokens_on_pass_total_range = float(out_of_range) / float(self.pass_number())

        #if out_of_range > len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE:
            #print out_of_range, len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE
        if out_of_range > self.pass_number() * ZERO_THRESHOLD_PASS_OUT_OF_TOTAL_RANGE:
            self.token_bucket_flag = RESULT_PASS_FILL_OUT_OF_RANGE
            return

        self.token_bucket_flag = 0
        return

    def check_policing_detector(self):
        self.set_late_loss_flag()
        self.set_token_bucket_flag()
        self.set_inflated_rtt_flag()

    def policing_detector(self):

        # RESULT_INSUFFICIENT_LOSS (1)
        #print self.loss_number(), self.pass_number(), self.node_pair_number
        #print (self.node_pair[0][0] == None), self.node_pair[0][2]

        if self.loss_number() < MIN_NUM_SAMPLES or self.pass_number() < MIN_NUM_SAMPLES:
            #print self.loss_number(), self.pass_number(), self.uncompress_nodes_number
            return 0

        # RESULT_LATE_LOSS (2)
        self.set_late_loss_flag()
        if self.late_loss_flag == 1:
            return 1

        # RESULT_NEGATIVE_FILL (3)
        # RESULT_HIGHER_FILL_ON_LOSS (4)
        # RESULT_LOSS_FILL_OUT_OF_RANGE (5)
        # RESULT_PASS_FILL_OUT_OF_RANGE (6)
        self.set_token_bucket_flag()
        if self.token_bucket_flag >= 1:
            return 2

        # RESULT_INFLATED_RTT (0)
        self.set_inflated_rtt_flag()
        if self.inflated_rtt_flag == 1:
            return 3

        return 4
