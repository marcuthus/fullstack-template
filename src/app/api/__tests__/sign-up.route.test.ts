import { beforeEach, describe, expect, it, vi } from "vitest"

import { POST } from "../auth/sign-up/route"
import { HttpError } from "@/helpers/auth.helper"
import * as authService from "@/services/auth.service"

vi.mock("@/services/auth.service", () => ({
    signUp: vi.fn(),
}))

describe("SignUp API Route", () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it("should return 201 when sign up is successful", async () => {
        const body = {
            name: "John Doe",
            email: "john@example.com",
            username: "johndoe",
            password: "password123",
        }

        const request = new Request("http://localhost:3000/api/auth/sign-up", {
            method: "POST",
            body: JSON.stringify(body),
        })

        vi.mocked(authService.signUp).mockResolvedValue({ id: "user-id", ...body } as any)

        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(201)
        expect(data.username).toBe("johndoe")
        expect(authService.signUp).toHaveBeenCalled()
    })

    it("should return 400 when validation fails", async () => {
        const body = {
            name: "J", // too short (min 2)
            email: "invalid-email",
            username: "jd", // too short (min 3)
            password: "123", // too short (min 6)
        }

        const request = new Request("http://localhost:3000/api/auth/sign-up", {
            method: "POST",
            body: JSON.stringify(body),
        })

        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.errors).toBeDefined()
        expect(Array.isArray(data.errors)).toBe(true)
    })

    it("should return 500 when server error occurs", async () => {
        const body = {
            name: "John Doe",
            email: "john@example.com",
            username: "johndoe",
            password: "password123",
        }

        const request = new Request("http://localhost:3000/api/auth/sign-up", {
            method: "POST",
            body: JSON.stringify(body),
        })

        vi.mocked(authService.signUp).mockRejectedValue(new Error("Database error"))

        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(500)
        // A mensagem interna não deve vazar para o cliente
        expect(data.message).toBe("Internal Server Error")
    })

    it("should return 409 when user already exists", async () => {
        const body = {
            name: "John Doe",
            email: "john@example.com",
            username: "johndoe",
            password: "password123",
        }

        const request = new Request("http://localhost:3000/api/auth/sign-up", {
            method: "POST",
            body: JSON.stringify(body),
        })

        vi.mocked(authService.signUp).mockRejectedValue(
            new HttpError(409, "Usuário ou e-mail já cadastrado")
        )

        const response = await POST(request)

        expect(response.status).toBe(409)
    })
})
