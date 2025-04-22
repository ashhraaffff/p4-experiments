# Self learning switch 
- This program dynamically populates the forwarding tables by observing incoming packets source and destination addresses using gRPC.
- Leverages the CPU port to send unmatched packets to CPU and to reinject the same back to the tofino pipeline after adding the forwarding rules.
