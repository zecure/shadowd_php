<p>The connector received a response from the <a href="https://shadowd.zecure.org">Shadow Daemon</a> server that could not be parsed.</p>
<p>A wrong address (host/port) might be specified in the configuration file of the <a href="https://shadowd.zecure.org/documentation/connectors/">connector</a>.</p>

<?php if (!$this->isDebug()): ?>
    <p>Enable the debug setting to get additional information about the processing error.</p>
<?php endif; ?>