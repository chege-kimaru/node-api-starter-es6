import AuthService from '../services/AuthService';
import Send from '../utils/Send';
import ReqValidator from '../utils/validator';

export default class AuthController {
    static async register(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                username: 'required',
                email: 'required',
                password: 'required',
            });
            if (!valid) return;

            const data = {
                username: req.body.username,
                email: req.body.email,
                password: req.body.password
            };

            Send.success(res, 201, await AuthService.createUser(data));
        } catch (err) {
            Send.error(res, err);
        }
    };

    static async verify(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                token: 'required'
            });
            if (!valid) return;

            const token = req.body.token;

            Send.success(res, 200, await AuthService.verifyToken(token));
        } catch (err) {
            Send.error(res, err);
        }
    };

    static async resendVerificationToken(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                email: 'required'
            });
            if (!valid) return;

            const email = req.body.email;

            Send.success(res, 200, await AuthService.resendVerificationToken(email));
        } catch (err) {
            Send.error(res, err);
        }
    };

    static async login(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                email: 'required|email',
                password: 'required',
            });
            if (!valid) return;

            const data = {
                email: req.body.email,
                password: req.body.password
            };

            Send.success(res, 200, await AuthService.login(data));
        } catch (err) {
            Send.error(res, err);
        }
    };

    static async changePassword(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                current_password: 'required',
                password: 'required',
            });
            if (!valid) return;

            const data = {
                current_password: req.body.current_password,
                password: req.body.password
            };

            Send.success(res, 200, await AuthService.changePassword(data, req.user.id));
        } catch (err) {
            Send.error(res, err);
        }
    };

    static async forgotPassword(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                email: 'required'
            });
            if (!valid) return;

            const email = req.body.email;

            Send.success(res, 200, await AuthService.forgotPassword(email));
        } catch (err) {
            Send.error(res, err);
        }
    };

    static async changeForgottenPassword(req, res) {
        try {
            const valid = await ReqValidator.validate(req, res, {
                token: 'required',
                password: 'required'
            });
            if (!valid) return;

            const data = {token: req.body.token, password: req.body.password};

            const email = req.body.email;

            Send.success(res, 200, await AuthService.changeForgottenPassword(data));
        } catch (err) {
            Send.error(res, err);
        }
    };
}
