namespace Earthware.Nancy.Authentication.Forms.Test
{
    using System;

    using Machine.Fakes;
    using Machine.Specifications;

    public class InMemoryAuthSessionIdStoreTests
    {
        public class context_for_in_memory_auth_session_id_store_tests : WithSubject<InMemoryAuthSessionIdStore>
        {
        }

        public class when_told_to_add_an_id : context_for_in_memory_auth_session_id_store_tests
        {
            static Guid result;

            static Guid input = Guid.NewGuid();

            Because of = () => result = Subject.Add(input, DateTime.UtcNow.AddMinutes(20));

            It should_return_a_guid = () => result.ShouldNotEqual(Guid.Empty);

            It should_return_a_guid_that_is_different_from_the_input = () => result.ShouldNotEqual(input);
        }

        public class when_told_to_get_an_id_with_a_session_id_that_is_valid : context_for_in_memory_auth_session_id_store_tests
        {
            static Guid authSessionId;

            static Guid userId = Guid.NewGuid();

            static Guid result;

            Establish context = () => authSessionId = Subject.Add(userId, DateTime.UtcNow.AddMinutes(20));

            Because of = () => result = Subject.Get(authSessionId);

            It should_return_the_expected_id = () => result.ShouldEqual(userId);
        }

        public class when_told_to_get_an_id_with_a_session_id_that_is_invalid : context_for_in_memory_auth_session_id_store_tests
        {
            static Guid authSessionId = Guid.NewGuid();

            static Guid result;

            Because of = () => result = Subject.Get(authSessionId);

            It should_return_an_empty_guid = () => result.ShouldEqual(Guid.Empty);
        }

        public class when_told_to_get_an_id_with_a_session_id_that_has_expired : context_for_in_memory_auth_session_id_store_tests
        {
            static Guid authSessionId;

            static Guid userId = Guid.NewGuid();

            static Guid result;

            Establish context = () => authSessionId = Subject.Add(userId, DateTime.UtcNow.AddMinutes(-20));

            Because of = () => result = Subject.Get(authSessionId);

            It should_return_an_empty_guid = () => result.ShouldEqual(Guid.Empty);
        }

        public class when_told_to_remove_a_session_id : context_for_in_memory_auth_session_id_store_tests
        {
            static Guid authSessionId;

            static Guid userId = Guid.NewGuid();

            Establish context = () => authSessionId = Subject.Add(userId, DateTime.UtcNow.AddMinutes(-20));

            Because of = () => Subject.Remove(authSessionId);

            It should_not_be_possible_to_retrieve_the_session_in_subsequent_calls =
                () => Subject.Get(authSessionId).ShouldEqual(Guid.Empty);
        }

        public class when_told_to_remove_a_session_id_and_the_session_id_is_invalid : context_for_in_memory_auth_session_id_store_tests
        {
            Because of = () => Subject.Remove(Guid.NewGuid());

            It should_not_throw_any_exceptions = () => true.ShouldBeTrue();
        }
    }
}