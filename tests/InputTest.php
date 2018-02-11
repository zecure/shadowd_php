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

namespace shadowd;

define('__MISC__', realpath(dirname(__FILE__)) . '/../misc/tests/');

class InputTest extends \PHPUnit\Framework\TestCase {
    public function testGetInput() {
        $_GET['foo'] = 'bar';
        $_POST['foo'] = 'bar';
        $_COOKIE['foo'] = 'bar';
        $_SERVER['HTTP_FOO'] = 'bar';
        $_SERVER['foo'] = 'bar';
        $_FILES['foo']['name'] = 'bar';

        $i = new Input();
        $input = $i->getInput();

        $this->assertTrue(array_key_exists('GET|foo', $input));
        $this->assertEquals($input['GET|foo'], 'bar');
        $this->assertTrue(array_key_exists('POST|foo', $input));
        $this->assertEquals($input['POST|foo'], 'bar');
        $this->assertTrue(array_key_exists('COOKIE|foo', $input));
        $this->assertEquals($input['COOKIE|foo'], 'bar');
        $this->assertTrue(array_key_exists('SERVER|HTTP_FOO', $input));
        $this->assertEquals($input['SERVER|HTTP_FOO'], 'bar');
        $this->assertFalse(array_key_exists('SERVER|foo', $input));
        $this->assertTrue(array_key_exists('FILES|foo', $input));
        $this->assertEquals($input['FILES|foo'], 'bar');
    }

    public function testFlatten() {
        $input = array(
            'foo' => 'bar',
            'boo' => array(
                'quz' => 'qoz'
            )
        );

        $i = new Input();
        $flattened = $i->flatten($input);

        $this->assertTrue(array_key_exists('foo', $flattened));
        $this->assertEquals($flattened['foo'], 'bar');
        $this->assertTrue(array_key_exists('boo|quz', $flattened));
        $this->assertEquals($flattened['boo|quz'], 'qoz');
    }

    public function testDefuseInput() {
        $_GET['foo'] = 'bar';
        $_POST['foo'] = 'bar';
        $_COOKIE['foo'] = 'bar';
        $_SERVER['HTTP_FOO'] = 'bar';
        $_FILES['foo']['name'] = 'bar';

        $i = new Input();
        $this->assertTrue($i->defuseInput(array(
            'GET|foo',
            'POST|foo',
            'COOKIE|foo',
            'SERVER|HTTP_FOO',
            'FILES|foo'
        )));

        $this->assertArrayNotHasKey('foo', $_GET);
        $this->assertArrayNotHasKey('foo', $_POST);
        $this->assertArrayNotHasKey('foo', $_REQUEST);
        $this->assertArrayNotHasKey('foo', $_COOKIE);
        $this->assertArrayNotHasKey('HTTP_FOO', $_SERVER);
        $this->assertArrayNotHasKey('foo', $_FILES);
    }

    public function testEscapeKey() {
        $i = new Input();

        $this->assertEquals($i->escapeKey('foo'), 'foo');
        $this->assertEquals($i->escapeKey('foo|bar'), 'foo\\|bar');
        $this->assertEquals($i->escapeKey('foo\\|bar'), 'foo\\\\\\|bar');
        $this->assertEquals($i->escapeKey('foo||bar'), 'foo\\|\\|bar');
        $this->assertEquals($i->escapeKey('foo\\\\bar'), 'foo\\\\\\\\bar');
    }

    public function testUnescapeKey() {
        $i = new Input();

        $this->assertEquals($i->unescapeKey('foo'), 'foo');
        $this->assertEquals($i->unescapeKey('foo\\|bar'), 'foo|bar');
        $this->assertEquals($i->unescapeKey('foo\\\\bar'), 'foo\\bar');
        $this->assertEquals($i->unescapeKey('foo\\\\\\|bar'), 'foo\\|bar');
    }

    public function testSplitSpath() {
        $i = new Input();

        $test1 = $i->splitPath('foo');
        $this->assertEquals(count($test1), 1);
        $this->assertEquals($test1[0], 'foo');

        $test2 = $i->splitPath('foo|bar');
        $this->assertEquals(count($test2), 2);
        $this->assertEquals($test2[0], 'foo');
        $this->assertEquals($test2[1], 'bar');

        $test3 = $i->splitPath('foo\\|bar');
        $this->assertEquals(count($test3), 1);
        $this->assertEquals($test3[0], 'foo\\|bar');

        $test4 = $i->splitPath('foo\\\\|bar');
        $this->assertEquals(count($test4), 2);
        $this->assertEquals($test4[0], 'foo\\\\');
        $this->assertEquals($test4[1], 'bar');

        $test5 = $i->splitPath('foo\\\\\\|bar');
        $this->assertEquals(count($test5), 1);
        $this->assertEquals($test5[0], 'foo\\\\\\|bar');

        $test6 = $i->splitPath('foo\\');
        $this->assertEquals(count($test6), 1);
        $this->assertEquals($test6[0], 'foo\\');
    }

    public function testRemoveIgnoredCaller() {
        $i = new Input(array(
            'callerKey'  => 'shadowd_caller',
            'ignoreFile' => __MISC__ . 'ignore1.json'
        ));
        $input = array(
            'GET|bar' => 'foobar'
        );

        $_SERVER['shadowd_caller'] = 'foo';
        $output = $i->removeIgnored($input);
        $this->assertArrayNotHasKey('GET|bar', $output);

        $_SERVER['shadowd_caller'] = 'boo';
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|bar', $output);
    }

    public function testRemoveIgnoredPath() {
        $i = new Input(array(
            'ignoreFile' => __MISC__ . 'ignore2.json'
        ));

        $input = array(
            'GET|bar' => 'foobar'
        );
        $output = $i->removeIgnored($input);
        $this->assertArrayNotHasKey('GET|bar', $output);

        $input = array(
            'GET|boo' => 'foobar'
        );
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|boo', $output);
    }

    public function testRemoveIgnoredCallerPath() {
        $i = new Input(array(
            'callerKey'  => 'shadowd_caller',
            'ignoreFile' => __MISC__ . 'ignore3.json'
        ));

        $_SERVER['shadowd_caller'] = 'foo';
        $input = array(
            'GET|bar' => 'foobar'
        );
        $output = $i->removeIgnored($input);
        $this->assertArrayNotHasKey('GET|bar', $output);

        $_SERVER['shadowd_caller'] = 'foo';
        $input = array(
            'GET|boo' => 'foobar'
        );
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|boo', $output);

        $_SERVER['shadowd_caller'] = 'boo';
        $input = array(
            'GET|bar' => 'foobar'
        );
        $output = $i->removeIgnored($input);
        $this->assertArrayHasKey('GET|bar', $output);
    }

    public function testGetHashes() {
        $_SERVER['SCRIPT_FILENAME'] = __MISC__ . 'hashes';

        $i = new Input();
        $hashes = $i->getHashes();

        $this->assertTrue(array_key_exists('sha256', $hashes));
        $this->assertEquals($hashes['sha256'], 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f');
    }
}
