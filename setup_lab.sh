#!/bin/bash
set -e

echo "[1/8] Cleaning old lab (if present)..."

sudo ip netns del hostA 2>/dev/null || true
sudo ip netns del hostB 2>/dev/null || true

sudo ip link del routerA 2>/dev/null || true
sudo ip link del routerB 2>/dev/null || true

echo "[2/8] Creating namespaces..."

sudo ip netns add hostA
sudo ip netns add hostB

echo "[3/8] Creating veth pairs..."

sudo ip link add vethA type veth peer name routerA
sudo ip link add vethB type veth peer name routerB

echo "[4/8] Moving interfaces into namespaces..."

sudo ip link set vethA netns hostA
sudo ip link set vethB netns hostB

echo "[5/8] Assigning IP addresses..."

sudo ip netns exec hostA ip addr add 10.0.0.2/24 dev vethA
sudo ip addr add 10.0.0.1/24 dev routerA

sudo ip netns exec hostB ip addr add 20.0.0.2/24 dev vethB
sudo ip addr add 20.0.0.1/24 dev routerB

echo "[6/8] Bringing interfaces up..."

sudo ip netns exec hostA ip link set lo up
sudo ip netns exec hostA ip link set vethA up

sudo ip netns exec hostB ip link set lo up
sudo ip netns exec hostB ip link set vethB up

sudo ip link set routerA up
sudo ip link set routerB up

echo "[7/8] Installing routes..."

sudo ip netns exec hostA ip route add default via 10.0.0.1

sudo ip netns exec hostB ip route add default via 20.0.0.1

echo "[8/8] Done."

echo
echo "Topology:"
echo
echo "hostA (10.0.0.2)"
echo "      |"
echo "    vethA"
echo "      |"
echo "   routerA (10.0.0.1)"
echo
echo "   SOFTWARE ROUTER"
echo
echo "   routerB (20.0.0.1)"
echo "      |"
echo "    vethB"
echo "      |"
echo "hostB (20.0.0.2)"
echo
echo "Quick tests:"
echo "sudo ip netns exec hostA ping 10.0.0.1"
echo "sudo ip netns exec hostB ping 20.0.0.1"