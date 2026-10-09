# Backgrounds a long sleep in this shell's process group, records its pid in the
# file named by the first argument, and waits on it. A timeout that kills only
# the shell leaves the sleep running; killing the group takes both.
sleep 30 &
echo "$!" > "$1.partial"
mv "$1.partial" "$1"
wait
