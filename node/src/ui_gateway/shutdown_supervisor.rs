// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

trait Signaler: Send {
    fn sigterm(&self);
}

struct SignalerReal {}

impl Signaler for SignalerReal {
    fn sigterm(&self) {
        std::process::exit(0);
    }
}

impl SignalerReal {
    fn new() -> SignalerReal {
        SignalerReal {}
    }
}

pub trait ShutdownSupervisor: Send {
    fn shutdown(&self);
}

pub struct ShutdownSupervisorReal {
    signaler: Box<dyn Signaler>,
}

impl ShutdownSupervisor for ShutdownSupervisorReal {
    fn shutdown(&self) {
        // TODO: Additional graceful-shutdown code should go here
        self.signaler.sigterm();
    }
}

impl ShutdownSupervisorReal {
    pub fn new() -> ShutdownSupervisorReal {
        ShutdownSupervisorReal {
            signaler: Box::new(SignalerReal::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct SignalerMock {
        sigterm_parameters: Arc<Mutex<Vec<()>>>,
    }

    impl Signaler for SignalerMock {
        fn sigterm(&self) {
            self.sigterm_parameters.lock().unwrap().push(());
        }
    }

    impl SignalerMock {
        fn new() -> SignalerMock {
            SignalerMock {
                sigterm_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        fn sigterm_parameters(self, parameters: &mut Arc<Mutex<Vec<()>>>) -> SignalerMock {
            *parameters = self.sigterm_parameters.clone();
            self
        }
    }

    #[test]
    fn shutdown_demand_triggers_signaler() {
        let mut subject = ShutdownSupervisorReal::new();
        let mut sigterm_parameters = Arc::new(Mutex::new(vec![]));
        let signaler = SignalerMock::new().sigterm_parameters(&mut sigterm_parameters);
        subject.signaler = Box::new(signaler);

        subject.shutdown();

        assert_eq!(sigterm_parameters.lock().unwrap().len(), 1);
    }
}
