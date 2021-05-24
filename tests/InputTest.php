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

use shadowd\Input;
use PHPUnit\Framework\TestCase;

class InputTest extends TestCase {
    public function testGetInput() {
        $_GET['foo'] = 'bar';
        $_POST['foo'] = 'bar';
        $_COOKIE['foo'] = 'bar';
        $_SERVER['HTTP_FOO'] = 'bar';
        $_SERVER['foo'] = 'bar';
        $_FILES['foo']['name'] = 'bar';

        $i = new Input([]);
        $input = $i->getInput();

        $this->assertTrue(array_key_exists('GET|foo', $input));
        $this->assertEquals('bar', $input['GET|foo']);
        $this->assertTrue(array_key_exists('POST|foo', $input));
        $this->assertEquals('bar', $input['POST|foo']);
        $this->assertTrue(array_key_exists('COOKIE|foo', $input));
        $this->assertEquals('bar', $input['COOKIE|foo']);
        $this->assertTrue(array_key_exists('SERVER|HTTP_FOO', $input));
        $this->assertEquals('bar', $input['SERVER|HTTP_FOO']);
        $this->assertFalse(array_key_exists('SERVER|foo', $input));
        $this->assertTrue(array_key_exists('FILES|foo', $input));
        $this->assertEquals('bar', $input['FILES|foo']);
    }

    public function testFlatten() {
        $input = [
            'foo' => 'bar',
            'boo' => [
                'quz' => 'qoz'
            ]
        ];

        $i = new Input([]);
        $flattened = $i->flatten($input);

        $this->assertTrue(array_key_exists('foo', $flattened));
        $this->assertEquals('bar', $flattened['foo']);
        $this->assertTrue(array_key_exists('boo|quz', $flattened));
        $this->assertEquals('qoz', $flattened['boo|quz']);
    }

    public function testDefuseInput() {
        $_GET['foo'] = 'bar';
        $_POST['foo'] = 'bar';
        $_COOKIE['foo'] = 'bar';
        $_SERVER['HTTP_FOO'] = 'bar';
        $_FILES['foo']['name'] = 'bar';

        $i = new Input([]);
        $this->assertTrue($i->defuseInput([
            'GET|foo',
            'POST|foo',
            'COOKIE|foo',
            'SERVER|HTTP_FOO',
            'FILES|foo'
        ]));

        $this->assertArrayNotHasKey('foo', $_GET);
        $this->assertArrayNotHasKey('foo', $_POST);
        $this->assertArrayNotHasKey('foo', $_REQUEST);
        $this->assertArrayNotHasKey('foo', $_COOKIE);
        $this->assertArrayNotHasKey('HTTP_FOO', $_SERVER);
        $this->assertArrayNotHasKey('foo', $_FILES);
    }

    public function testEscapeKey() {
        $i = new Input([]);

        $this->assertEquals('foo', $i->escapeKey('foo'));
        $this->assertEquals('foo\\|bar', $i->escapeKey('foo|bar'));
        $this->assertEquals('foo\\\\\\|bar', $i->escapeKey('foo\\|bar'));
        $this->assertEquals('foo\\|\\|bar', $i->escapeKey('foo||bar'));
        $this->assertEquals('foo\\\\\\\\bar', $i->escapeKey('foo\\\\bar'));
    }

    public function testUnescapeKey() {
        $i = new Input([]);

        $this->assertEquals('foo', $i->unescapeKey('foo'));
        $this->assertEquals('foo|bar', $i->unescapeKey('foo\\|bar'));
        $this->assertEquals('foo\\bar', $i->unescapeKey('foo\\\\bar'));
        $this->assertEquals('foo\\|bar', $i->unescapeKey('foo\\\\\\|bar'));
    }

    public function testSplitSpath() {
        $i = new Input([]);

        $test1 = $i->splitPath('foo');
        $this->assertEquals(1, count($test1));
        $this->assertEquals('foo', $test1[0]);

        $test2 = $i->splitPath('foo|bar');
        $this->assertEquals(2, count($test2));
        $this->assertEquals('foo', $test2[0]);
        $this->assertEquals('bar', $test2[1]);

        $test3 = $i->splitPath('foo\\|bar');
        $this->assertEquals(1, count($test3));
        $this->assertEquals('foo\\|bar', $test3[0]);

        $test4 = $i->splitPath('foo\\\\|bar');
        $this->assertEquals(2, count($test4));
        $this->assertEquals('foo\\\\', $test4[0]);
        $this->assertEquals('bar', $test4[1]);

        $test5 = $i->splitPath('foo\\\\\\|bar');
        $this->assertEquals(1, count($test5));
        $this->assertEquals('foo\\\\\\|bar', $test5[0]);

        $test6 = $i->splitPath('foo\\');
        $this->assertEquals(1, count($test6));
        $this->assertEquals('foo\\', $test6[0]);
    }

    public function testRemoveIgnoredCaller() {
        $i = new Input([
            'callerKey'  => 'shadowd_caller',
            'ignoreFile' => SHADOWD_MISC_TESTS . 'ignore1.json'
        ]);
        $input = [
            'GET|bar' => 'foobar'
        ];

        $_SERVER['shadowd_caller'] = 'foo';
        $output = $i->removeIgnored($input);
        $this->assertArrayNotHasKey('GET|bar', $output);

        $_SERVER['shadowd_caller'] = 'boo';
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|bar', $output);
    }

    public function testRemoveIgnoredPath() {
        $i = new Input([
            'ignoreFile' => SHADOWD_MISC_TESTS . 'ignore2.json'
        ]);

        $input = [
            'GET|bar' => 'foobar'
        ];
        $output = $i->removeIgnored($input);
        $this->assertArrayNotHasKey('GET|bar', $output);

        $input = [
            'GET|boo' => 'foobar'
        ];
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|boo', $output);
    }

    public function testRemoveIgnoredCallerPath() {
        $i = new Input([
            'callerKey'  => 'shadowd_caller',
            'ignoreFile' => SHADOWD_MISC_TESTS . 'ignore3.json'
        ]);

        $_SERVER['shadowd_caller'] = 'foo';
        $input = [
            'GET|bar' => 'foobar'
        ];
        $output = $i->removeIgnored($input);
        $this->assertArrayNotHasKey('GET|bar', $output);

        $_SERVER['shadowd_caller'] = 'foo';
        $input = [
            'GET|boo' => 'foobar'
        ];
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|boo', $output);

        $_SERVER['shadowd_caller'] = 'boo';
        $input = [
            'GET|bar' => 'foobar'
        ];
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|bar', $output);
    }

    public function testGetHashes() {
        $_SERVER['SCRIPT_FILENAME'] = SHADOWD_MISC_TESTS . 'hashes';

        $i = new Input([]);
        $hashes = $i->getHashes();

        $this->assertTrue(array_key_exists('sha256', $hashes));
        $this->assertEquals('aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f', $hashes['sha256']);
    }
}
