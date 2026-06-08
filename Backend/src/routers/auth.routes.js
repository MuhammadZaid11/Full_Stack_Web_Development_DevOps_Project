const { Router } = require('express');
const authController = require('../controllers/auth.controller');

const router = Router();

// basic runtime checks to surface missing controller methods early
['registerUserController', 'loginUserController', 'logoutUserController'].forEach(fn => {
	if (typeof authController[fn] !== 'function') {
		throw new Error(`auth.controller is missing required export: ${fn}`);
	}
});

router.post('/register', authController.registerUserController);
router.post('/login', authController.loginUserController);
router.get('/logout', authController.logoutUserController);

module.exports = router;