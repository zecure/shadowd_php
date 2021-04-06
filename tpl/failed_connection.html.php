<p>
    No connection could be established with the <a href="https://shadowd.zecure.org">Shadow Daemon</a> server.
    The server is either unreachable or the wrong address is specified in the configuration file of the <a href="https://shadowd.zecure.org/documentation/connectors/">connector</a>.
</p>

<?php if (!$this->isDebug()): ?>
    <p>Enable the debug setting to get additional information about the failed connection.</p>
<?php endif; ?>