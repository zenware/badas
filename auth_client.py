import zmq

context = zmq.Context()

socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5555")

print("Sending auth request ...")
socket.send(b"user:pass")

message = socket.recv()
print("Received response [ %s ]" % message)
