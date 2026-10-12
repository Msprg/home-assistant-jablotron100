"""Post-write verification compares sections and PGs as the panel stores them."""

from __future__ import annotations

from jablotron_api.domain.models import UserCreateModel, UserModel, UserPatchModel
import jablotron_api.services.user_manager as user_manager
from test_user_patch_carry_over import _verify_error


def test_post_add_verification_ignores_the_order_of_sections_and_pgs():
    user = UserModel(id=4, name="Guard 4", section_ids=[1, 2], pg_ids=[1, 3])
    payload = UserCreateModel(id=4, name="Guard 4", sections=[2, 1], pgs=[3, 1])
    assert _verify_error(user_manager.verify_added_user, user, payload) is None


def test_post_edit_verification_ignores_the_order_of_sections_and_pgs():
    user = UserModel(id=4, name="Guard 4", section_ids=[1, 2], pg_ids=[1, 3])
    payload = UserPatchModel(sections=[2, 1], pgs=[3, 1])
    assert _verify_error(user_manager.verify_edited_user, user, payload) is None


def test_post_write_verification_still_reports_a_real_difference():
    user = UserModel(id=4, name="Guard 4", section_ids=[1, 2], pg_ids=[1, 3])
    added = _verify_error(
        user_manager.verify_added_user, user, UserCreateModel(id=4, name="Guard 4", sections=[1, 3])
    )
    edited = _verify_error(user_manager.verify_edited_user, user, UserPatchModel(pgs=[1]))
    assert added == "User 4 post-add verification failed for: sections."
    assert edited == "User 4 post-edit verification failed for: pgs."
