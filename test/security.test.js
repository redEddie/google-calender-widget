const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { test } = require('node:test');
const { configureSecurity, isCalendarUrl } = require('../security');

const calendarUrl = 'https://calendar.google.com/calendar/u/0/r/agenda';

const createWindow = () => {
    const contents = new EventEmitter();
    const externalUrls = [];
    const loadedUrls = [];
    contents.url = calendarUrl;
    contents.getURL = () => contents.url;
    contents.loadURL = async (url) => loadedUrls.push(url);
    contents.setWindowOpenHandler = (handler) => { contents.openWindow = handler; };
    contents.session = {
        setPermissionRequestHandler(handler) { this.requestPermission = handler; },
        setPermissionCheckHandler(handler) { this.checkPermission = handler; },
    };
    configureSecurity({ webContents: contents }, async (url) => externalUrls.push(url));
    return { contents, externalUrls, loadedUrls };
};

const navigate = (contents, name, url, isMainFrame = true) => {
    const event = {
        url,
        isMainFrame,
        defaultPrevented: false,
        preventDefault() { this.defaultPrevented = true; },
    };
    contents.emit(name, event);
    return event;
};

test('only exact HTTPS Google origins are trusted', () => {
    const { contents, loadedUrls } = createWindow();
    assert.equal(isCalendarUrl(calendarUrl), true);
    assert.equal(isCalendarUrl('https://CALENDAR.GOOGLE.COM:443/calendar'), true);
    assert.equal(isCalendarUrl('https://accounts.google.com'), false);

    const untrustedUrls = [
        'https://calendar.google.com.attacker.example/',
        'https://attacker.example/?next=https://calendar.google.com',
        'https://calendar.google.com@attacker.example/',
        'https://attacker@calendar.google.com/',
        'https://calendar.google.com:444/',
        'https://calendar.google.com./',
        'http://calendar.google.com/',
        'blob:https://calendar.google.com/1234',
        'file:///C:/Windows/System32/calc.exe',
        'javascript:alert(document.cookie)',
        'data:text/html,<script>alert(1)</script>',
        'ms-settings:privacy',
        '//calendar.google.com/calendar',
        'invalid',
        '',
        undefined,
    ];
    for (const url of untrustedUrls) {
        assert.equal(navigate(contents, 'will-navigate', url).defaultPrevented, true, String(url));
        assert.equal(isCalendarUrl(url), false, String(url));
    }
    assert.deepEqual(loadedUrls, []);
});

test('Google login and calendar navigation stay inside the existing window', () => {
    const { contents, loadedUrls, externalUrls } = createWindow();
    const loginUrl = 'https://accounts.google.com/ServiceLogin';
    assert.equal(navigate(contents, 'will-navigate', loginUrl).defaultPrevented, false);
    assert.deepEqual(contents.openWindow({ url: loginUrl }), { action: 'deny' });
    assert.deepEqual(loadedUrls, [loginUrl]);
    assert.deepEqual(externalUrls, []);
});

test('ordinary external web links open in the system browser', () => {
    const { contents, loadedUrls, externalUrls } = createWindow();
    const linkUrl = 'https://meet.google.com/abc-defg-hij';
    assert.equal(navigate(contents, 'will-navigate', linkUrl).defaultPrevented, true);
    assert.deepEqual(contents.openWindow({ url: 'http://example.com/event' }), { action: 'deny' });
    assert.deepEqual(externalUrls, [linkUrl, 'http://example.com/event']);
    assert.deepEqual(loadedUrls, []);
});

test('executable protocols and credential-bearing URLs never reach the OS shell', () => {
    const { contents, loadedUrls, externalUrls } = createWindow();
    for (const url of [
        'file:///C:/Windows/System32/calc.exe',
        'javascript:alert(1)',
        'data:text/html,hello',
        'ms-settings:privacy',
        'https://calendar.google.com@attacker.example/',
        'invalid',
    ]) {
        assert.equal(navigate(contents, 'will-navigate', url).defaultPrevented, true);
        assert.deepEqual(contents.openWindow({ url }), { action: 'deny' });
    }
    assert.deepEqual(loadedUrls, []);
    assert.deepEqual(externalUrls, []);
});

test('redirects cannot leave the trusted top-level origins', () => {
    const { contents, externalUrls } = createWindow();
    assert.equal(navigate(contents, 'will-redirect', calendarUrl).defaultPrevented, false);
    assert.equal(navigate(contents, 'will-redirect', 'https://accounts.google.com/').defaultPrevented, false);
    assert.equal(navigate(contents, 'will-redirect', 'https://attacker.example/').defaultPrevented, true);
    assert.equal(navigate(contents, 'will-redirect', 'file:///C:/secret').defaultPrevented, true);
    assert.equal(navigate(contents, 'will-redirect', 'https://www.gstatic.com/', false).defaultPrevented, false);
    assert.deepEqual(externalUrls, []);
});

test('only the calendar origin in this calendar window can request notifications', () => {
    const { contents } = createWindow();
    const { session } = contents;
    const request = (permission, requestingUrl, requestContents = contents) => {
        let result;
        session.requestPermission(requestContents, permission, (allowed) => { result = allowed; }, { requestingUrl });
        return result;
    };
    assert.equal(request('notifications', calendarUrl), true);
    assert.equal(session.checkPermission(contents, 'notifications', 'https://calendar.google.com'), true);

    for (const permission of ['media', 'geolocation', 'clipboard-read', 'display-capture', 'usb', 'unknown']) {
        assert.equal(request(permission, calendarUrl), false);
        assert.equal(session.checkPermission(contents, permission, 'https://calendar.google.com'), false);
    }
    for (const origin of ['https://attacker.example', 'https://accounts.google.com', 'https://calendar.google.com.attacker.example']) {
        assert.equal(request('notifications', origin), false);
        assert.equal(session.checkPermission(contents, 'notifications', origin), false);
    }
    assert.equal(request('notifications', calendarUrl, null), false);
    assert.equal(request('notifications', calendarUrl, new EventEmitter()), false);
    assert.equal(session.checkPermission(null, 'notifications', 'https://calendar.google.com'), false);
    contents.url = 'https://accounts.google.com/';
    assert.equal(request('notifications', calendarUrl), false);
    assert.equal(session.checkPermission(contents, 'notifications', 'https://calendar.google.com'), false);
});

test('permission requests with missing origin details fail closed', () => {
    const { contents } = createWindow();
    let result;
    contents.session.requestPermission(contents, 'notifications', (allowed) => { result = allowed; });
    assert.equal(result, false);
});

test('failed external browser launches are handled', async () => {
    const { contents } = createWindow();
    configureSecurity({ webContents: contents }, async () => { throw new Error('unavailable'); });
    const originalError = console.error;
    const errors = [];
    console.error = (message) => errors.push(message);
    try {
        contents.openWindow({ url: 'https://example.com/' });
        await Promise.resolve();
        assert.deepEqual(errors, ['Could not open the external web link.']);
    } finally {
        console.error = originalError;
    }
});
