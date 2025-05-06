import json
import logging
import hashlib
import os
from nfstream import NFStreamer
from datetime import datetime

# Configure logging
logging.basicConfig(filename='flow_tracker.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Output directory for JSON files
output_folder = "flow_data"
os.makedirs(output_folder, exist_ok=True)

# Generate timestamp for output file
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
flow_file = os.path.join(output_folder, f"flows_{timestamp}.json")

def generate_flow_id(flow):
    """Generate a unique FlowID from flow 5-tuple."""
    try:
        five_tuple = (
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol
        )
        return hashlib.md5(str(five_tuple).encode()).hexdigest()[:8]
    except Exception as e:
        logging.error(f"Error generating FlowID: {e}")
        return None

def compile_flow_json(flow):
    """Compile flow features into JSON with FlowID."""
    try:
        flow_id = generate_flow_id(flow)
        if not flow_id:
            logging.warning(f"Skipping flow with invalid ID: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
            return None

        # Log flow details for debugging
        logging.debug(f"Processing flow {flow_id}: src={flow.src_ip}:{flow.src_port}, dst={flow.dst_ip}:{flow.dst_port}, protocol={flow.protocol}, packets={flow.bidirectional_packets}")

        # Map NFStream features to requested fields (using correct attribute names)
        flow_data = {
            "FlowID": f"flow{flow_id}",
            "Flow_IAT_Mean": getattr(flow, 'bidirectional_mean_iat', 0.0) / 1000,  # ms to seconds
            "Idle_Mean": 0.0,  # Placeholder; NFStream doesn't compute idle times
            "Fwd_IAT_Mean": getattr(flow, 'src2dst_mean_iat', 0.0) / 1000,
            "Packet_Length_Mean": getattr(flow, 'bidirectional_mean_piat', 0.0),
            "Fwd_Packet_Length_Mean": getattr(flow, 'src2dst_mean_piat', 0.0),
            "Flow_IAT_Std": getattr(flow, 'bidirectional_std_iat', 0.0) / 1000,
            "Fwd_Packet_Length_Min": getattr(flow, 'src2dst_min_piat', 0.0),
            "Idle_Min": 0.0,  # Placeholder
            "Flow_IAT_Min": getattr(flow, 'bidirectional_min_iat', 0.0) / 1000,
            "Init_Fwd_Win_Bytes": getattr(flow, 'src2dst_init_windows_size', 0),
            "Packet_Length_Variance": getattr(flow, 'bidirectional_variance_piat', 0.0),
            "CWE_Flag_Count": getattr(flow, 'src2dst_cwr_packets', 0),
            "Protocol": flow.protocol,
            "Flow_Packets_per_s": flow.bidirectional_packets / (flow.bidirectional_duration_ms / 1000) if flow.bidirectional_duration_ms else 0.0,
            "Fwd_Packets_per_s": flow.src2dst_packets / (flow.bidirectional_duration_ms / 1000) if flow.bidirectional_duration_ms else 0.0,
            "Fwd_PSH_Flags": getattr(flow, 'src2dst_psh_packets', 0),
            "Fwd_Act_Data_Packets": getattr(flow, 'src2dst_data_packets', 0),
            "Fwd_IAT_Std": getattr(flow, 'src2dst_std_iat', 0.0) / 1000,
            "Avg_Fwd_Segment_Size": getattr(flow, 'src2dst_mean_piat', 0.0),
            "Flow_IAT_Max": getattr(flow, 'bidirectional_max_iat', 0.0) / 1000,
            "Total_Fwd_Packets": flow.src2dst_packets,
            "Subflow_Fwd_Packets": flow.src2dst_packets / flow.bidirectional_packets if flow.bidirectional_packets else 0.0,
            "Fwd_IAT_Min": getattr(flow, 'src2dst_min_iat', 0.0) / 1000,
            "URG_Flag_Count": getattr(flow, 'src2dst_urg_packets', 0),
            "ACK_Flag_Count": getattr(flow, 'src2dst_ack_packets', 0),
            "RST_Flag_Count": getattr(flow, 'src2dst_rst_packets', 0),
            "Fwd_Packet_Length_Std": getattr(flow, 'src2dst_std_piat', 0.0),
            "Fwd_IAT_Max": getattr(flow, 'src2dst_max_iat', 0.0) / 1000,
            "Packet_Length_Min": getattr(flow, 'bidirectional_min_piat', 0.0),
            "Active_Max": flow.bidirectional_duration_ms / 1000  # Flow duration in seconds
        }
        return flow_data
    except Exception as e:
        logging.error(f"Error compiling flow JSON for flow {flow_id}: {e}")
        return None

def main():
    """Main function to track flows and save features."""
    try:
        # Initialize NFStreamer for live capture (replace 'eth0' with your interface)
        streamer = NFStreamer(
            source="enp0s3",  # Or use a pcap file, e.g., "capture.pcap"
            statistical_analysis=True,
            idle_timeout=10,  # Flow expires after 10s of inactivity
            active_timeout=120,  # Flow expires after 120s max duration
            splt_analysis=10  # Analyze first 10 packets for L7 protocols
        )

        # Open output file
        with open(flow_file, "a") as flow_f:
            for flow in streamer:
                try:
                    # Compile flow features into JSON
                    flow_json = compile_flow_json(flow)
                    if not flow_json:
                        continue

                    # Write flow JSON to file
                    flow_f.write(json.dumps(flow_json) + "\n")
                    flow_f.flush()
                    logging.info(f"Processed flow {flow_json['FlowID']}")
                    print(f"Flow JSON: {json.dumps(flow_json, indent=2)}")

                except Exception as e:
                    logging.error(f"Error processing flow: {e}")
                    continue

    except Exception as e:
        logging.error(f"Streamer error: {e}")
        print(f"Streamer stopped: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped by user")
        logging.info("Script stopped by user")
    except Exception as e:
        logging.error(f"Script error: {e}")
        print(f"Script error: {e}")
