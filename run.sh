./cli/.libs/babeltrace run -c s:source.ctf.lttng-live --key url --value net://localhost/host/dn9/new-session -c f:filter.utils.muxer -c w:sink.text.dnfiles -C s:f -C f:w
