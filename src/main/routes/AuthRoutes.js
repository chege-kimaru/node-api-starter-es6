import { Router } from 'express';
import AuthController from '../controllers/AuthController';
import Auth from "../middlewares/Auth";
const router = Router();

router.post('/register', AuthController.register);
router.post('/verify/resend', AuthController.resendVerificationToken);
router.post('/verify', AuthController.verify);
router.post('/login', AuthController.login);
router.post('/change-password', Auth, AuthController.changePassword);
router.post('/forgot-password', AuthController.forgotPassword);
router.post('/forgot-password-change', AuthController.changeForgottenPassword);


export default router;
