import {sequelize, User, UserVerificationToken, ForgotPasswordToken} from '../db/models';
import {Op} from 'sequelize';
import {
    ResourceNotFoundError,
    AuthenticationError,
    OperationNotAllowedError,
    AuthorizationError
} from '../utils/errors';
import bcrypt from 'bcrypt';
import Logger from '../utils/logger';
import jwt from 'jsonwebtoken';
import uuid from 'uuid/v4';
import moment from 'moment';
import Mailer from "../utils/mailer";

const logger = new Logger().logger();

const sendVerificationEmail = async (user, token) => {
    const m = new Mailer();
    await m.send({
        template: 'userVerification',
        message: {
            to: user.email
        },
        locals: {
            user: user,
            token: token
        }
    });
};

const sendForgotPasswordEmail = async (user, token) => {
    const m = new Mailer();
    await m.send({
        template: 'forgotPassword',
        message: {
            to: user.email
        },
        locals: {
            user: user.email,
            token
        }
    });
};

export default class AuthService {
    static async createUser(data) {
        try {
            data.password = await bcrypt.hash(data.password, +process.env.BCRYPT_SALT);
            let user = await User.findOne({where: {username: data.username}});
            if (user && user.id) throw new OperationNotAllowedError('This username is not available');
            user = await User.findOne({where: {email: data.email}});
            if (user && user.id) throw new OperationNotAllowedError('This email already has an account linked to it.');
            return sequelize.transaction(transaction => {
                return User.create(data, {transaction}).then(user => {
                    return UserVerificationToken.create({
                        user_id: user.id,
                        token: uuid(),
                        expiry: moment().add(+process.env.USER_VERIFICATION_TOKEN_EXPIRY_HOURS, "hours")
                    }, {transaction}).then(token => {
                        sendVerificationEmail(user, token);
                        let user_ = user.dataValues;
                        delete user_.password;
                        return user_;
                    })
                });
            });
        } catch (err) {
            throw(err);
        }
    };

    static findByPk(id) {
        return User.findByPk(id).then(user => {
            let user_ = user.dataValues;
            delete user_.password;
            return user_;
        });
    };

    static verifyToken(token) {
        return UserVerificationToken.findOne({where: {token}}).then(token => {
            if (!token || !token.id) throw new OperationNotAllowedError('Verification failed. Please use the link sent to your email.');
            if (new Date() > token.expiry) throw new OperationNotAllowedError('Verification failed. This link has expired. Please request for a new one.');
            return token.getUser().then(user => {
                if (user.verified) throw new OperationNotAllowedError('This account is already verified. Please login to continue.');
                return user.update({verified: true}).then(user => {
                    let user_ = user.dataValues;
                    delete user_.password;
                    return user_;
                });
            })
        })
    };

    static resendVerificationToken(email) {
        return User.findOne({where: {email}}).then(user => {
            if (!user || !user.id) throw new ResourceNotFoundError('This account does not exist');
            if (user.verified) throw new OperationNotAllowedError('This account has already been verified');
            return user.getUserVerificationToken().then(token => {
                if (token && token.id)
                    return token.update({
                        token: uuid(),
                        expiry: moment().add(+process.env.USER_VERIFICATION_TOKEN_EXPIRY_HOURS, "hours")
                    }).then(token => {
                        return sendVerificationEmail(user, token).then(data => {
                            return {data: 'Verification token resent.'};
                        });
                    });
                else
                    return UserVerificationToken.create({
                        user_id: user.id,
                        token: uuid(),
                        expiry: moment().add(+process.env.USER_VERIFICATION_TOKEN_EXPIRY_HOURS, "hours")
                    }).then(token => {
                        return sendVerificationEmail(user, token).then(data => {
                            return {data: 'Verification token resent.'};
                        });
                    });
            });
        });
    };

    static async login(data) {
        try {
            const user = await User.findOne({where: {email: data.email}});
            if (user && user.id && await bcrypt.compare(data.password, user.password)) {
                let user_ = user.dataValues;
                const payload = {id: user.id};
                user_.jwt = await jwt.sign(payload, process.env.SECRET_OR_KEY);
                delete user_.password;
                return user_;
            } else {
                throw new AuthenticationError('Wrong Credentials.');
            }
        } catch (err) {
            throw(err);
        }
    };

    static async changePassword(data, userId) {
        const user = await User.findByPk(userId);
        if (!user || !user.id) throw new AuthorizationError('You are not authorized to perform this operation');
        if (await bcrypt.compare(data.current_password, user.password)) {
            return user.update({password: await bcrypt.hash(data.password, +process.env.BCRYPT_SALT)}).then(user => {
                let user_ = user.dataValues;
                delete user_.password;
                return user_;
            });
        } else {
            throw new AuthenticationError('Wrong credentials. Please input correct password.');
        }
    };

    static forgotPassword(email) {
        return User.findOne({where: {email}}).then(user => {
            if (!user || !user.id) throw new ResourceNotFoundError('This account does not exist');

            return user.getForgotPasswordToken().then(token => {
                if (token && token.id)
                    return token.update({
                        used: false,
                        token: uuid(),
                        expiry: moment().add(+process.env.FORGOT_PASSWORD_TOKEN_EXPIRY_HOURS, "hours")
                    }).then(token => {
                        return sendForgotPasswordEmail(user, token).then(data => {
                            return {data: 'Forgot password id sent to your email.'};
                        });
                    });
                else
                    return ForgotPasswordToken.create({
                        user_id: user.id,
                        used: false,
                        token: uuid(),
                        expiry: moment().add(+process.env.FORGOT_PASSWORD_TOKEN_EXPIRY_HOURS, "hours")
                    }).then(token => {
                        return sendForgotPasswordEmail(user, token).then(data => {
                            return {data: 'Forgot password id sent to your email.'};
                        });
                    });
            });
        });
    };

    static async changeForgottenPassword(data) {
        return ForgotPasswordToken.findOne({where: {token: data.token}}).then(token => {
            if (!token || !token.id) throw new OperationNotAllowedError('Invalid token. Please use the link sent to your email.');
            if (token.used) throw new OperationNotAllowedError('Invalid token. This token has already been used. Please request for another.');
            if (new Date() > token.expiry) throw new OperationNotAllowedError('Invalid token. This link has expired. Please request for a new one.');
            return sequelize.transaction(transaction => {
                return token.getUser({transaction}).then(async user => {
                    return user.update({password: await bcrypt.hash(data.password, +process.env.BCRYPT_SALT)}, {transaction})
                        .then(user => {
                            return token.update({used: true}).then(token => {
                                let user_ = user.dataValues;
                                delete user_.password;
                                return user_;
                            });
                        });
                })
            });
        })
    };
}
