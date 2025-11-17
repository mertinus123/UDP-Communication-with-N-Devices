@startuml
skinparam style strictuml

actor Application

Application -> Publisher: send_async(tuples)
Publisher -> SendQueue: enqueue()
SendQueue --> Publisher: OK

loop SenderThread
    Publisher -> SendQueue: dequeue()
    SendQueue --> Publisher: Request
    alt small batch
        Publisher -> UDP Socket: send single packet
    else fragmented batch
        loop fragments
            Publisher -> PacketPool: acquire()
            PacketPool --> Publisher: Packet*
            Publisher -> UDP Socket: sendto()
            Publisher -> PacketPool: release()
        end
    end
end

== Receiving ==

Subscriber -> UDP Socket: recvfrom()
UDP Socket --> Subscriber: packet

Subscriber -> BatchReassembler: add_fragment()
alt batch complete
    BatchReassembler --> Subscriber: CompleteBatch
    Subscriber -> Statistics: record_receive()
else incomplete
    BatchReassembler --> Subscriber: null
end

@enduml
