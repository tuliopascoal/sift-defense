# sift-defense
SIFT defense approach for SDN controllers for Slow-TCAM attacks mitigation.

In order to apply SIFT, you need to add SIFT-related code snippets to your current controller.
Basically, it will keep your controller monitoring for TABLE_FULL OpenFlow messages and taking actions against malicious flow entry rules.

For more details and understanding of SIFT and Slow-TCAM attacks, please check my paper called "Slow-TCAM Exhaustion DDoS Attack" in IFIP SEC 2017 [1]:

Pascoal, T. A., Dantas, Y. G., Fonseca, I. E., Nigam, V., 2017. "Slow TCAM Exhaustion DDoS Attack." In 32nd IFIP International Conference on ICT Systems Security and Privacy Protection, pp. 17-31. Springer, Cham, 2017.

----------------------------------------------------------------------------------------------
Files:

cpu_mem_log.sh: shell script for CPU and memory monitoring consumption of SIFT controller;
sift_uniform.py: SIFT controller with selective strategy (uniform distribution);
sift_PPCount.py: SIFT controller with selective strategy based on "packet_count" of flow entry rules; (still under testing)
sift_PBCount.py: SIFT controller with selective strategy based on "byte_count" of flow entry rules; (still under testing)
