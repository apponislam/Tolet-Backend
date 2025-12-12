import { Router } from "express";
import auth from "../../middlewares/auth";
import { userControllers } from "./user.controllers";
import authorize from "../../middlewares/authorize";
import { roles } from "../auth/auth.interface";

const router = Router();

// router.get("/", auth, authorize([roles.ADMIN, roles.SUPER_ADMIN, roles.MODERATOR]), userControllers.getAllUser);

router.get("/", userControllers.getAllUsers);
router.get("/:id", userControllers.getSingleUser);

router.delete("/delete/me", auth, userControllers.deleteMyAccount);

router.delete("/delete/:id", auth, authorize([roles.ADMIN]), userControllers.adminDeleteUser);

export const userRoutes = router;
