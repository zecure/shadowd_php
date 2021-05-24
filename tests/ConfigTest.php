<?php

/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2016 Hendrik Buchwald <hb@zecure.org>
 *
 * This file is part of Shadow Daemon. Shadow Daemon is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use shadowd\Config;
use shadowd\Exceptions\CorruptedFileException;
use shadowd\Exceptions\MissingConfigEntryException;
use shadowd\Exceptions\MissingFileException;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase {
    public function testConstructorCorruptedFile() {
        $this->expectException(CorruptedFileException::class);
        new Config(SHADOWD_MISC_TESTS . '/connectors_invalid.ini', '');
    }

    public function testConstructorMissingFile() {
        $this->expectException(MissingFileException::class);
        new Config(SHADOWD_MISC_TESTS . '/notfound', '');
    }

    public function testGet() {
        $config = new Config(SHADOWD_MISC_TESTS . '/connectors_valid.ini', 'shadowd_php');

        $optionalValue1 = $config->get('notfound');
        $this->assertFalse($optionalValue1);

        $optionalValue2 = $config->get('profile');
        $this->assertEquals('1', $optionalValue2);

        $requiredValue = $config->get('profile', true);
        $this->assertEquals('1', $requiredValue);
    }

    public function testGetMissingEntry() {
        $config = new Config(SHADOWD_MISC_TESTS . '/connectors_valid.ini', '');

        $this->expectException(MissingConfigEntryException::class);
        $config->get('notfound', true);
    }
}
