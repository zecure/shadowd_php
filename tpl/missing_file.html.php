<p>A required file to initialize the <a href="https://shadowd.zecure.org">Shadow Daemon</a> web application firewall is missing.</p>
<p>This indicates that the <a href="https://shadowd.zecure.org/overview/php_connector/">installation</a> is incomplete or corrupted. The error can also be caused by insufficient permissions to access a required file.</p>

<?php if (!$this->isDebug()): ?>
    <p>Enable the debug setting to get additional information about the missing file.</p>
<?php endif; ?>