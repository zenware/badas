import zmq

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5555")

while True:
    message = socket.recv()
    credentials = message.split(":")
    print("Received request: %s" % message)

    if credentials[0] == 'root' and credentials[1] == 'password':
        socket.send(b"Success!")
    else:
        socket.send(b"Wrong password for %s" % credentials[0])
