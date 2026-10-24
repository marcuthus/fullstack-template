import { beforeEach, describe, expect, it, vi } from "vitest"

import { PATCH } from "../users/[id]/route"
import * as userService from "@/services/user.service"
import * as jwtUtil from "@/utils/jwt.util"

vi.mock("@/utils/jwt.util", () => ({
    verifyToken: vi.fn(),
}))

vi.mock("@/services/user.service", () => ({
    deleteUser: vi.fn(),
    findUserById: vi.fn(),
    updateUser: vi.fn(),
    verifyUserPassword: vi.fn(),
}))

function patchRequest(body: unknown) {
    return new Request("http://localhost:3000/api/users/user-1", {
        method: "PATCH",
        headers: { Authorization: "Bearer token" },
        body: JSON.stringify(body),
    })
}

const params = { params: Promise.resolve({ id: "user-1" }) }

describe("PATCH /api/users/[id]", () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(jwtUtil.verifyToken).mockReturnValue({
            sub: "user-1",
            type: "access",
            role: "USER",
        })
        vi.mocked(userService.updateUser).mockResolvedValue({ id: "user-1" } as any)
    })

    it("exige a senha atual para trocar a própria senha", async () => {
        vi.mocked(userService.verifyUserPassword).mockResolvedValue(false)

        const response = await PATCH(patchRequest({ password: "novaSenha123" }), params)

        expect(response.status).toBe(401)
        expect(userService.updateUser).not.toHaveBeenCalled()
    })

    it("troca a senha quando a senha atual confere", async () => {
        vi.mocked(userService.verifyUserPassword).mockResolvedValue(true)

        const response = await PATCH(
            patchRequest({ password: "novaSenha123", currentPassword: "senhaAtual" }),
            params
        )

        expect(response.status).toBe(200)
        expect(userService.updateUser).toHaveBeenCalledWith("user-1", { password: "novaSenha123" })
    })

    it("não permite editar outro usuário", async () => {
        vi.mocked(jwtUtil.verifyToken).mockReturnValue({
            sub: "user-2",
            type: "access",
            role: "USER",
        })

        const response = await PATCH(patchRequest({ name: "Outro" }), params)

        expect(response.status).toBe(403)
    })
})
