IN this practical we will see how the dhcp dora process works in real time in wire shark 

first of all write ipconfig in the command prompt to see your ip address or iwconfig for linux systems

```ipconfig```




🔄 Step 1: ipconfig /release
Your computer tells the DHCP server: “I’m giving up my current IP.”

```ipconfig /release```

It sends a DHCP Release packet to the server.

The server marks that IP as free in its pool.

Your device now has no valid IP (you’ll see 0.0.0.0 as the source in Wireshark).


🔄 Step 2: ipconfig /renew
This triggers the full DORA process:

Discover

``` ipconfig /renew```

Your device broadcasts: “Is there any DHCP server out there?”

Source IP: 0.0.0.0 (because you don’t have one yet).

Destination: 255.255.255.255 (broadcast to everyone).

Offer

The DHCP server replies: “I can give you this IP (e.g., 192.168.100.52), plus subnet mask, gateway, DNS, and lease time.”

This is the DHCP Offer packet you saw in Wireshark.

Request

Your device says: “I’d like to use that IP you offered.”

This is the DHCP Request packet.

Acknowledge (ACK)

The server confirms: “Okay, that IP is yours for the lease period.”

This is the DHCP ACK packet.

Your device now configures itself with the new IP, subnet mask, gateway, and DNS.

📊 What You Saw in Wireshark
`Release` → Your laptop gave up its old IP.

`Discover` → Broadcast from 0.0.0.0 asking for a new IP.

`Offer` → Server replied with an available IP.

`Request` → Laptop asked to use that IP.

`ACK` → Server confirmed the lease.

That’s the full handshake that happens every time a device joins a network or renews its IP.

👉 In simple terms:

Release = “I’m done with this IP.”

Renew = “Please give me a new one.”

DORA = The conversation between your device and the DHCP server to make that happen.
