import type { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import crypto from 'crypto';

class AuthController {
    async login(_: Request, __: Response, ___: NextFunction) {
        passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' });
    }

    async logout(req: Request, res: Response, next: NextFunction) {
        req.logout(function (err) {
            if (err) {
                return next(err);
            }
            res.redirect('/');
        });
    }

    async signup(req: Request, res: Response, next: NextFunction) {
        var salt = crypto.randomBytes(16);
        crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function (err, hashedPassword) {
            if (err) {
                return next(err);
            }
            db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [req.body.username, hashedPassword, salt], function (err) {
                if (err) {
                    return next(err);
                }
                var user = {
                    id: this.lastID,
                    username: req.body.username
                };
                req.login(user, function (err) {
                    if (err) {
                        return next(err);
                    }
                    res.redirect('/');
                });
            });
        });
    }

    async checkPassword(username: string, password: string, cb: (error: any, user?: Express.User | false, options?: any) => void) {
        db.get('SELECT * FROM users WHERE username = ?', [username], function (err, user) {
            if (err) {
                return cb(err);
            }
            if (!user) {
                return cb(null, false, { message: 'Incorrect username or password.' });
            }

            crypto.pbkdf2(password, user.salt, 310000, 32, 'sha256', function (err, hashedPassword) {
                if (err) {
                    return cb(err);
                }

                if (!crypto.timingSafeEqual(user.hashed_password, hashedPassword)) {
                    return cb(null, false, { message: 'Incorrect username or password.' });
                }

                return cb(null, user);
            });
        });
    }
}

export default new AuthController();
