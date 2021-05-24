<p>No connection could be established with the <a href="https://shadowd.zecure.org">Shadow Daemon</a> server.</p>
<?php if (!empty($this->getExceptionMessage())): ?>
    <p>The server is either unreachable or the wrong address is specified in the configuration file of the <a href="https://shadowd.zecure.org/documentation/connectors/">connector</a>.</p>
    <?php if (!$this->isDebug()): ?>
        <p>Enable the debug setting to get additional information.</p>
    <?php endif; ?>
<?php else: ?>
    <p>The exact cause is not known. It might be related to an invalid SSL public key.</p>
<?php endif; ?>