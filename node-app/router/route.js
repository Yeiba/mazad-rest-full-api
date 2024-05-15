import { Router } from "express";
const router = Router();

/** import all controllers */
import * as controller from '../controllers/appController.js';
import * as cach from '../middleware/cach.js';
import Auth from '../middleware/auth.js';

// Post Methods

router.route('/register').post(controller.register); // register user
// router.route('/registerMail').post();
router.route('/authenticate').post(controller.verifyUser, (req, res) => res.end());
router.route('/login').post(controller.verifyUser, controller.login);
router.route('/logout').post(controller.logout);


// Get Methods
router.route('/isAuth').get(Auth)
router.route('/user/profile').get(Auth, cach.getProfileFromCach, controller.getProfile).put(Auth, controller.updateUser).delete(Auth, controller.deleteUser) // user with username
router.route('/users/:username').get(cach.getUserFromCach, controller.getUser) // user with username
router.route('/users').get(cach.getUsersFromCash, controller.getUsers) // user with username

router.route('/generateOTP').get(controller.generateOTP);
router.route('/sendOTP').post(controller.sendOTP);
router.route('/verifyOTP').post(controller.verifyOTP);
router.route('/createResetSession').get(controller.createResetSession);

// Put Methods
router.route('/resetPassword').put(controller.resetPassword);



export default router;