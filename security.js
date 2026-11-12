const CALENDAR_ORIGIN = 'https://calendar.google.com';
const ACCOUNTS_ORIGIN = 'https://accounts.google.com';
const APP_ORIGINS = new Set([CALENDAR_ORIGIN, ACCOUNTS_ORIGIN]);

const parseUrl = (value) => {
    try {
        return new URL(value);
    } catch {
        return null;
    }
};

const getHttpsOrigin = (value) => {
    const url = parseUrl(value);
    return url?.protocol === 'https:' && !url.username && !url.password ? url.origin : null;
};

const isAppUrl = (value) => APP_ORIGINS.has(getHttpsOrigin(value));
const isCalendarUrl = (value) => getHttpsOrigin(value) === CALENDAR_ORIGIN;
const isCalendarProductPage = (value) => (
    getHttpsOrigin(value) === 'https://workspace.google.com' &&
    /^\/(?:intl\/[a-z\d-]+\/)?products\/calendar\/?$/i.test(new URL(value).pathname)
);

const calendarSignInUrl = (calendarUrl) => {
    const url = new URL('/ServiceLogin', ACCOUNTS_ORIGIN);
    url.searchParams.set('service', 'cl');
    url.searchParams.set('continue', calendarUrl);
    return url.href;
};

const configureSecurity = (mainWindow, openExternal) => {
    const contents = mainWindow.webContents;
    let pendingCalendarUrl;

    const openGooglePage = (url) => {
        contents.loadURL(url).catch(() => {
            console.error('Could not open the Google page.');
        });
    };

    const openExternalLink = (value) => {
        const url = parseUrl(value);
        if (!url || url.username || url.password || !['https:', 'http:'].includes(url.protocol)) {
            return;
        }

        openExternal(url.href).catch(() => {
            console.error('Could not open the external web link.');
        });
    };

    contents.setWindowOpenHandler(({ url }) => {
        if (isAppUrl(url)) {
            openGooglePage(url);
        } else {
            openExternalLink(url);
        }
        return { action: 'deny' };
    });

    contents.on('will-navigate', (event) => {
        if (!isAppUrl(event.url)) {
            event.preventDefault();
            openExternalLink(event.url);
        }
    });

    contents.on('did-start-navigation', (event) => {
        if (event.isMainFrame && !event.isSameDocument) {
            pendingCalendarUrl = isCalendarUrl(event.url) ? event.url : undefined;
        }
    });

    contents.on('will-redirect', (event) => {
        if (!event.isMainFrame || isAppUrl(event.url)) return;
        event.preventDefault();

        // A signed-out Calendar request can send users to the Workspace product page.
        // Use the interactive Google sign-in link and return to the requested calendar.
        if (!pendingCalendarUrl || !isCalendarProductPage(event.url)) return;
        const signInUrl = calendarSignInUrl(pendingCalendarUrl);
        pendingCalendarUrl = undefined;
        setImmediate(() => {
            if (!contents.isDestroyed()) openGooglePage(signInUrl);
        });
    });

    const allowNotification = (requestContents, permission, requestingUrl) => {
        return requestContents === contents &&
            permission === 'notifications' &&
            isCalendarUrl(contents.getURL()) &&
            isCalendarUrl(requestingUrl);
    };

    contents.session.setPermissionRequestHandler((requestContents, permission, callback, details) => {
        callback(allowNotification(requestContents, permission, details?.requestingUrl));
    });

    contents.session.setPermissionCheckHandler((requestContents, permission, requestingOrigin) => {
        return allowNotification(requestContents, permission, requestingOrigin);
    });
};

module.exports = { configureSecurity, isCalendarUrl };
